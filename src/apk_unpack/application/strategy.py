from __future__ import annotations

from typing import Any


def _step(tool: str, *, method: str | None = None, reason: str = "", requires: list[str] | None = None) -> dict[str, Any]:
    return {
        "tool": tool,
        "method": method,
        "reason": reason,
        "requires": requires or [],
    }


def recommend_strategy(
    inspection: dict[str, Any],
    device: dict[str, Any] | None = None,
    process: dict[str, Any] | None = None,
    *,
    force_dump: bool = False,
) -> dict[str, Any]:
    """Choose a deterministic, evidence-backed unpacking route.

    The knowledge base is explicit that the same shell can behave differently per
    APK, so this returns a primary route plus an ordered fallback chain and a
    do-not-attempt list rather than a single unconditional recipe.
    """

    packing = inspection.get("packing") or {}
    shell = packing.get("primary") or "unknown"
    layers = {item.get("shell") for item in packing.get("layers") or []}
    frameworks = {item.get("name") for item in inspection.get("frameworks") or []}
    abis = set(inspection.get("abis") or [])
    device_abi = (device or {}).get("abi") or ""
    device_root = bool((device or {}).get("root", {}).get("available"))
    process = process or {}
    tracer_pid = (process.get("status") or {}).get("tracer_pid", process.get("tracer_pid"))
    packed = packing.get("packed")
    limitations: list[str] = list(inspection.get("limitations") or [])

    arm_only_on_x86 = bool(
        device_abi in ("x86", "x86_64")
        and abis
        and not any(abi in abis for abi in ("x86", "x86_64"))
    )

    steps: list[dict[str, Any]] = []
    fallbacks: list[str] = []
    do_not_attempt: list[str] = []
    risks: list[str] = []
    notes: list[str] = []
    prerequisites: list[str] = ["authorization to test the supplied APK"]
    confidence = "derived"
    if "flutter" in frameworks:
        notes.append(
            "Flutter: business logic may be in lib/<abi>/libapp.so; a DEX dump will not recover it. Use Flutter-specific tooling."
        )
    if "react-native" in frameworks:
        notes.append(
            "React Native: inspect assets/index.android.bundle; DEX may only contain the host shell."
        )
    if inspection.get("split_apk"):
        notes.append(
            "Split APK detected: only base classes may be present; assemble all splits before concluding coverage."
        )

    if force_dump:
        notes.append("force_dump requested: execute a runtime DEX dump even when static sources are available.")

    if "uni-app" in frameworks and not force_dump:
        return {
            "shell": shell,
            "framework": "uni-app",
            "primary": "static_wgt",
            "steps": [
                _step("extract_apk_assets", reason="uni-app ships an unencrypted wgt; static extraction often avoids dynamic unpacking entirely."),
            ],
            "fallbacks": ["inspect_apk"],
            "do_not_attempt": [],
            "prerequisites": prerequisites,
            "risks": ["wgt may be absent from a split APK or may not contain all business logic."],
            "notes": notes + ["Prefer static wgt extraction before any Frida or memory work."],
            "confidence": "observed",
        }

    if packed is False and shell == "unknown" and not force_dump:
        return {
            "shell": "unknown",
            "framework": None,
            "primary": "static_jadx",
            "steps": [
                _step("decompile_android_apk", reason="No shell indicators and a normal class count; decompile the APK directly."),
            ],
            "fallbacks": [],
            "do_not_attempt": ["dump_android_dex"],
            "prerequisites": prerequisites,
            "risks": [],
            "notes": notes + ["Packed=false is derived from top-level DEX headers; runtime code loading remains possible."],
            "confidence": "observed",
        }

    prerequisites.append("rooted Android device or root-capable emulator")

    if shell == "bangcle" or "bangcle" in layers:
        confidence = "observed"
        steps = [
            _step("inspect_android_device", reason="Confirm root, ABI, frida-server state."),
            _step("prepare_android_environment", reason="Ensure root and (when needed) a matching frida-server; Bangcle is usually Frida-immune."),
            _step("launch_android_target", reason="Start the app and capture the PID."),
            _step("inspect_process_state", reason="Read maps/TracerPid and rank libc_malloc/heap regions."),
            _step(
                "dump_android_dex",
                method="memory_dd",
                reason="Root /proc/pid/mem dump is the only reliable route for Bangcle.",
            ),
        ]
        fallbacks = ["memory_dd_retry", "freeze_dd"]
        do_not_attempt = ["frida_inmemory", "frida_inmemory_spawn", "frida_mcookie"]
        risks.append("Bangcle uses fake dlsym, 0xdead0000 and inline-syscall anti-debug; Frida attempts waste rounds.")
        notes.append(
            "If the first dd misses the crash window, memory_dd_retry relaunches and uses the fast bs ladder; "
            "freeze is generalized to libc_malloc/[heap] for Bangcle."
        )
        if arm_only_on_x86:
            notes.append("APK is ARM-only on an x86/x86_64 device (Houdini). Prefer bs=1024 crash-window dumping or freeze_dd.")
            fallbacks = ["memory_dd_retry", "freeze_dd"]
        return _result(shell, steps, fallbacks, do_not_attempt, prerequisites, risks, notes, confidence, device_root, limitations)

    if shell == "360" or "360" in layers:
        confidence = "observed"
        inner_secneo = "secneo" in layers
        if inner_secneo:
            notes.append("360 outer + SecNeo inner: prepare_android_environment should rename libSdkHelper_sdk.so (reversible) before attaching.")
        steps = [
            _step("inspect_android_device", reason="Confirm root, ABI and frida-server state."),
            _step(
                "prepare_android_environment",
                reason="Start Frida and, for a 360+SecNeo build, apply the reversible inner-library bypass.",
                requires=["inner_bypass"] if inner_secneo else [],
            ),
            _step("launch_android_target", reason="Start the app and capture the PID."),
            _step("inspect_process_state", reason="Check TracerPid and process survival before injecting."),
            _step(
                "dump_android_dex",
                method="frida_mcookie",
                reason="360 references DEX through multiple native DexFile* cookie pointers; dump every cookie.",
            ),
        ]
        fallbacks = ["frida_mcookie_spawn_anti_kill"]
        do_not_attempt = ["memory_dd"]
        risks.append("360 DEX is not reliably discoverable by dd; a TracerPid!=0 anti-debug blocks attach.")
        if tracer_pid not in (None, 0):
            notes.append("TracerPid is non-zero: try one spawn+anti-kill pass, then move to an ARM64 physical device.")
            fallbacks = ["frida_mcookie_spawn_anti_kill", "arm64_device_fallback"]
        return _result(shell, steps, fallbacks, do_not_attempt, prerequisites, risks, notes, confidence, device_root, limitations)

    if shell == "tencent":
        confidence = "observed"
        steps = [
            _step("inspect_android_device", reason="Confirm root/run-as and Frida state."),
            _step("prepare_android_environment", reason="Start frida-server and forward the port."),
            _step("launch_android_target", reason="Start the app so MTP writes decrypted DEX to disk."),
            _step(
                "dump_android_dex",
                method="disk_pull",
                reason="MTP leaves decrypted DEX under files/prodexdir; attach and pull is the simplest route.",
            ),
        ]
        fallbacks = ["frida_inmemory"]
        do_not_attempt = []
        risks.append("MTP placeholder classes2/3.dex are tiny; only prodexdir files are real.")
        return _result(shell, steps, fallbacks, do_not_attempt, prerequisites, risks, notes, confidence, device_root, limitations)

    if shell == "ijiami":
        confidence = "observed"
        steps = [
            _step("inspect_android_device", reason="Confirm root, ABI and frida-server version match."),
            _step("prepare_android_environment", reason="Start frida-server and forward the port."),
            _step("launch_android_target", reason="Observe stability before choosing spawn or attach."),
            _step("inspect_process_state", reason="Check TracerPid, process lifetime and dalvik-DEX maps."),
            _step(
                "dump_android_dex",
                method="frida_inmemory",
                reason="Try spawn/attach with cookie + NativeFunction fwrite first.",
            ),
        ]
        fallbacks = ["frida_inmemory_spawn", "memory_dd", "freeze_dd"]
        do_not_attempt = []
        risks.append("ijiami may use inline syscall suicide; libc-level anti-kill hooks are not sufficient.")
        if arm_only_on_x86:
            notes.append("ARM-only APK on an x86/x86_64 device: expect Houdini and short crash windows; keep freeze_dd ready.")
        if tracer_pid not in (None, 0):
            notes.append(
                "TracerPid is non-zero: attach may be blocked; try one spawn+anti-kill pass, then memory_dd/freeze_dd."
            )
            fallbacks = ["frida_inmemory_spawn", "memory_dd", "freeze_dd"]
        return _result(shell, steps, fallbacks, do_not_attempt, prerequisites, risks, notes, confidence, device_root, limitations)

    if shell == "secneo" or "secneo" in layers:
        confidence = "inferred"
        steps = [
            _step("prepare_android_environment", reason="Apply the reversible SecNeo library bypass.", requires=["inner_bypass"]),
            _step("launch_android_target", reason="Start the app and confirm it survives."),
            _step("dump_android_dex", method="frida_mcookie", reason="Try cookie extraction after the inner SDK is bypassed."),
        ]
        fallbacks = ["memory_dd", "freeze_dd"]
        do_not_attempt = []
        risks.append("SecNeo SDK may be a normal dependency rather than the outer shell; verify the crash trace first.")
        return _result(shell, steps, fallbacks, do_not_attempt, prerequisites, risks, notes, confidence, device_root, limitations)

    confidence = "inferred"
    steps = [
        _step("inspect_android_device", reason="Confirm root, ABI and Frida state."),
        _step("prepare_android_environment", reason="Start frida-server."),
        _step("launch_android_target", reason="Observe stability."),
        _step("inspect_process_state", reason="Check TracerPid and candidate DEX regions."),
        _step("dump_android_dex", method="frida_inmemory", reason="Unknown shell: try the least invasive Frida route first."),
    ]
    fallbacks = ["frida_inmemory_spawn", "memory_dd_retry", "freeze_dd"]
    risks.append("Unknown shell: do not assume anti-debug strength; stop after one failed Frida attempt.")
    return _result(shell, steps, fallbacks, do_not_attempt, prerequisites, risks, notes, confidence, device_root, limitations)


def _result(
    shell: str,
    steps: list[dict[str, Any]],
    fallbacks: list[str],
    do_not_attempt: list[str],
    prerequisites: list[str],
    risks: list[str],
    notes: list[str],
    confidence: str,
    device_root: bool,
    limitations: list[str],
) -> dict[str, Any]:
    if not device_root:
        prerequisites = list(dict.fromkeys(prerequisites + ["root check must pass before memory_dd"]))
    return {
        "shell": shell,
        "framework": None,
        "primary": steps[-1]["method"] if steps and steps[-1].get("method") else "inspect",
        "steps": steps,
        "fallbacks": fallbacks,
        "do_not_attempt": do_not_attempt,
        "prerequisites": prerequisites,
        "risks": risks,
        "notes": notes,
        "confidence": confidence,
        "limitations": limitations,
    }
