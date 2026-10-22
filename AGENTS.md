# AGENTS.md — operating rules for APK Unpack Agents

This repository mirrors REA's architecture: a small domain, explicit tool
contracts, a CLI/MCP split, content-addressed Evidence, and an installable agent
skill. These rules apply to humans and agents changing or using the tool.

## Authority and scope

- Only analyze APKs you own or are explicitly authorized to test. The tool does
  not grant authorization and must not be used for stealth, persistence, or
  anti-forensics on third-party apps.
- The source APK is read-only. Repair, extraction, and decompilation write only
  to a run directory or an explicitly supplied output directory.
- Do not install or upgrade Node, Python, adb, Frida, Java, JADX, aapt, or other
  external tools. `doctor` reports missing prerequisites; `setup` only installs
  this project's skill and MCP entry.
- Full automation is the default, but device changes must be reversible and
  recorded. Never remove the mutation log or skip `cleanup_run` after a
  successful investigation.

## Architecture

- Dependency direction: `domain → contracts → application/providers → CLI/MCP`.
  Domain code must not import providers or CLI. Providers must not import the
  CLI.
- All tool behavior is implemented once in `application/workflow.py`. CLI and
  MCP are transport adapters over the same service.
- Add a tool by updating three places together: `contracts/tools.py` (schema,
  effects, description), `application/workflow.py` (implementation and
  `TOOL_METHODS`), and the CLI mapping in `cli.py`. Then update
  `docs/mcp-contracts.md` and, when relevant, the skill references.
- Evidence-producing tools return an inline Evidence record (`ev_<sha256>`)
  with confidence, authority, limitations, and locations. Large artifacts are
  referenced by path + SHA-256, never embedded in Evidence.

## Evidence semantics

- `observed` means the provider read it from the artifact/device.
- `derived` means a deterministic computation over observed facts (for example,
  a strategy recommendation from shell + ABI + TracerPid).
- `inferred` means an analyst-style hypothesis that must be verified.
- Missing coverage is `unknown`, not absence. A valid DEX checksum proves
  internal consistency, not that every class was recovered.
- Do not claim runtime success from static evidence. Frida/dd results that were
  not executed on a device must be labeled unverified.

## Lessons / memory

- The persistent lesson store lives under `APU_MEMORY_DIR` (default
  `%LOCALAPPDATA%\apk-unpack\memory`). It is historical evidence, not authority.
- `dump_android_dex` and `launch_android_target` record observed fallbacks and
  emulator-detection bypasses automatically. Do not duplicate them manually.
- Record a manual lesson when a genuinely new scenario, shell variant, pitfall,
  or workaround is verified. Include symptoms, root cause, solution, scope, and
  `run:...`/`ev:...` links.
- `recommend_unpack_strategy` may reorder fallbacks or set `learned_primary`.
  Never let a lesson promote a method listed in `do_not_attempt`.
- A lesson is promoted only after repetition: two observations can reorder
  fallbacks; three can set a learned primary. One observation is not a rule.
- Never store credentials, tokens, APK bytes, or unrelated user data. Do not
  delete `lessons.json` silently; back it up first.

## Full-automation guardrails

1. Never modify the APK signature, repack, or patch the on-disk APK.
2. Record every device mutation (`rename_device_lib`, `frida_server_start`,
   `adb_forward`, `push_file`, `kill_stop`, `install_apk`, `force_stop`) with an
   apply/restore command.
3. `SIGSTOP` must be paired with `SIGCONT` in `finally` and in `cleanup_run`.
4. Only kill the Frida server PID we started.
5. Refuse to overwrite an existing `.apu.bak` that we do not own.
6. Installing an APK is allowed only with `allow_install=true` and is never
   automatically uninstalled.
7. Restore mutations in reverse order. If a restore fails, keep the run and
   return `cleanup_incomplete` with exact paths.
8. Stop after one failed Frida attempt per method. Bangcle is Frida-immune;
   360 cannot be recovered by dd; do not loop.

## Writing and testing

- Use `python -m unittest discover -s tests -v`. Offline tests use synthetic
  APK/DEX/maps fixtures and fake executables. Device tests require
  `APU_DEVICE_TESTS=1`.
- Keep stdout clean in MCP mode: protocol lines only. All logs go to stderr or
  run logs.
- Use absolute paths in tests and subprocess argv lists; never route device
  operations through Git Bash.
- When changing a shell signature, update `providers/apk.py`,
  `.agents/skills/unpack-android-apk/references/shell-signatures.md`, and the
  fixture matrix together.
