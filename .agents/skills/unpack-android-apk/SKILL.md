---
name: unpack-android-apk
description: Unpack hardened Android APKs (ijiami/爱加密, Bangcle/梆梆, 360 Jiagu/360加固, Tencent MTP/腾讯加固, SecNeo) with static routing, Frida cookie/in-memory dumps, and root /proc/pid/mem recovery. Use when an APK is shelled or packed (脱壳/加固), jadx shows only a stub, or DEX extraction/repair/verification is requested. Requires authorization and a rooted debugging device.
metadata:
  version: "1"
---

# APK Unpack Agents

Use this skill when a claim depends on code that a shell protector has hidden
from jadx, or when the user asks to 脱壳 / unpack / dump DEX from a packed APK.
For an ordinary unhardened APK that jadx already decompiles, use normal static
analysis and skip this skill.

Only analyze APKs you own or are explicitly authorized to test. The tool never
grants authorization. Start every non-trivial investigation with
`inspect_apk`; do not guess the shell from the filename.

## Connect only when needed

If the `apk-unpack` MCP tools are available, use them directly. If they are
absent, use the CLI as a fallback:

```powershell
$env:PYTHONPATH = "C:\path\to\apk-unpack-agents\src"
python -m apk_unpack <command> [--json]
```

Do not reinstall tools or rerun `setup` before every task. If a required
provider is missing, run `doctor` and report the exact missing prerequisite.
REA-style setup never installs adb, Frida, Java, JADX, aapt, or frida-server.

## Route the target first

1. `inspect_apk` — package, ABIs, frameworks, top-level DEX headers, shell layers,
   packed flag, and inline Evidence. This creates the run id used by every
   follow-up tool.
2. `recommend_unpack_strategy` — primary route, fallback chain, prerequisites,
   risks, and do-not-attempt list. Read it before executing anything.
3. If the APK is uni-app with a `__UNI__*.wgt`, prefer
   `extract_apk_assets` and stop; dynamic unpacking is often unnecessary.
4. Otherwise: `inspect_android_device` → `prepare_android_environment` →
   `launch_android_target` → `inspect_process_state` → `dump_android_dex` →
   `repair_android_dex` → `verify_android_dex` → optional
   `decompile_android_apk` → `cleanup_run`.
   If the package is not installed, use `unpack --install` or
   `prepare_android_environment` with `allow_install=true`; base + same-package
   sibling split APKs are installed with `install-multiple`.

Shell-specific defaults:

| Shell | First route | Never do |
|---|---|---|
| ijiami / 爱加密 | Frida cookie/in-memory dump; fall back to dalvik-DEX dd / freeze | Assume spawn and attach both work |
| Bangcle / 梆梆 | root `/proc/pid/mem` dd of `libc_malloc`/heap | Spend more than one Frida attempt |
| 360 Jiagu | Frida mCookie (all cookie pointers); SecNeo inner lib bypass when needed | Try dd as a shortcut |
| Tencent MTP | Frida attach → pull on-disk `files/prodexdir/*.dex` | Treat placeholder classes2/3.dex as real |
| Unknown | attach once, spawn once, then dd | Loop the same failed attempt |

Read [routing](references/routing.md) and [strategies](references/strategies.md)
for the full decision tree.

## Work summary-first

Start with the default result and its inline Evidence. Do not repeat an
identical analysis or rejected call; change an input or read the Evidence
first. When a result is large, use `get_evidence` / `inspect_run` and page it
rather than dumping everything into context.

Every conclusion must distinguish:

- **observed** — read from the APK, device, or process;
- **derived** — deterministic computation over observed facts;
- **inferred** — a hypothesis still requiring verification.

Cite the `ev_...` id and the relevant limitation. A DEX checksum proves
internal consistency, not complete recovery. A region score is a heuristic,
not proof a DEX is present.

## Full-automation guardrails

The tool may launch the app, inject Frida, read `/proc/pid/mem`, SIGSTOP a
process, and rename device libraries. Keep these rules:

1. Never modify, repack, or patch the source APK.
2. Every device change is recorded in `mutations.json`. `apu unpack` runs
   `cleanup_run` automatically; when composing individual tools, call
   `cleanup_run` at the end (`unpack --no-cleanup` keeps the live device state).
3. `SIGSTOP` is always paired with `SIGCONT` in `finally`; if a run is
   interrupted, call `cleanup_run`.
4. Only kill the frida-server PID this run started.
5. If a Frida attempt fails, do not retry the same method repeatedly. Move to
   the documented fallback.
6. If the app self-destructs, poll maps for `dalvik-DEX` and freeze before
   dumping; do not use a fixed sleep.
7. If a restore fails, keep the run and report `cleanup_incomplete` with paths.

## Learn from every run

The agent has a persistent lesson store. It makes future runs more accurate
without letting historical guesses override documented safety rules.

- `recommend_unpack_strategy` already embeds relevant lessons and
  `learned_adjustments`. Read them before changing the plan.
- `dump_android_dex` and `launch_android_target` automatically record observed
  fallbacks and emulator-detection bypasses (including failure symptoms,
  winning method, device ABI, and `run:...`/`ev:...` links).
- When you discover a genuinely new scenario, pitfall, or solution that is not
  captured automatically, call `remember_unpack_lesson` with concrete symptoms,
  root cause, solution, scope, and evidence. Do not duplicate automatic lessons.
- Use `recall_unpack_lessons` when debugging a familiar symptom or when you need
  more context than the strategy summary provides.
- Lessons are historical evidence, not proof. Check `scope`, `occurrences`,
  `success_count`, and `limitations`. Never let a lesson promote a method listed
  in `do_not_attempt` (for example dd on 360 or Frida on Bangcle).
- Never store credentials, tokens, APK bytes, or unrelated user data. The store
  redacts common secret patterns, but do not rely on it.
- Repeated lessons are promoted only after observed repetition: two successes
  can reorder fallbacks, three can promote a learned primary. One run is not a
  universal rule. See [lessons](references/lessons.md).

## Read only the relevant guide

- [shell signatures](references/shell-signatures.md)
- [strategy decision tree](references/strategies.md)
- [Frida cookie/in-memory dump](references/frida-cookie-dump.md)
- [memory dd and freeze](references/memory-dump.md)
- [DEX repair and verification](references/dex-forensics.md)
- [environment and Windows pitfalls](references/environment.md)
- [case matrix](references/cases.md)
- [Evidence and cleanup](references/evidence.md)
- [persistent lessons](references/lessons.md)

## Finish the task

Report, in this order:

1. run id and the shell/route actually taken;
2. artifacts (`dexdump/fixed/classes*.dex`) with sizes, class counts, SHA-256;
3. verification status and what remains unknown;
4. device mutations and cleanup status;
5. if decompiled, the JADX output path and Java file count.

If the process died, attach was blocked, or the dump was incomplete, say so
plainly and give the next documented fallback instead of claiming success.
