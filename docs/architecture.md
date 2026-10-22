# 架构

## 分层

```
domain/       纯数据与规则：Result、AnalysisError、Evidence、RunWorkspace、MapRegion
contracts/    ToolSpec：名称、描述、JSON Schema、effects、annotations
application/  strategy 决策树 + workflow 工具实现 + memory 经验库（唯一业务逻辑入口）
providers/    apk/axml/adb/process/memory/frida/dex/jadx 适配器
cli.py        argparse 传输层
mcp_server.py 零依赖 JSON-RPC stdio 传输层
```

依赖方向：`domain → contracts → application/providers → CLI/MCP`。
CLI 与 MCP 调用同一个 `ToolService`，避免两套行为。

## 一次完整运行

```
inspect_apk
  ├─ zipfile 读中央目录（不解压整包）
  ├─ aapt 优先 / 最小 AXML 兜底
  ├─ 顶层 classes*.dex 只读 112 字节 header
  ├─ 壳签名（ZIP 条目 / DEX 字符串 / Manifest）
  └─ 创建 run，写入 Evidence
recommend_unpack_strategy
  └─ 壳 + ABI + 框架 + 设备/进程事实 → primary/fallbacks/do_not_attempt
inspect_android_device
  └─ adb 设备/root/ABI/SDK/frida-server
prepare_android_environment
  └─ root、push/start frida-server、forward、可逆库改名，全部记入 mutations
launch_android_target
  └─ force-stop、am start、pidof、/proc status
inspect_process_state
  └─ TracerPid、maps、候选区域评分
dump_android_dex
  ├─ frida_inmemory / frida_mcookie → dump_cookie.js → pull
  ├─ disk_pull → disk_path.js → pull prodexdir
  ├─ memory_dd → /proc/pid/mem dd → 扫 dex magic
  └─ freeze_dd → 轮询 dalvik-DEX → SIGSTOP → dd → SIGCONT
repair_android_dex
  └─ 权威 file_size、SHA-1、Adler32、去重、classes*.dex
verify_android_dex
  └─ magic/header/checksum/signature/class 表/包名类统计
decompile_android_apk
  └─ jadx CLI
cleanup_run
  └─ 逆序恢复设备改动、SIGCONT、移除临时文件
```

## Frida 子进程

没有第三方 Frida Python bindings，所以：

- 生成一次性 wrapper：`preamble.js` + 操作脚本 + 内嵌配置。
- 宿主用 `subprocess` 启动 `frida -H ... -p/-f ... -l wrapper -q`。
- 脚本用 `console.log("APU::json")` 输出事件。
- 宿主看到 `done` 后终止 CLI；attach 不影响 App，spawn 会结束被启动进程。
- 超时/取消时 terminate → kill，并记录清理状态。

## 内存 dump

- maps 保留完整路径（含空格）。
- 按区域评分排序；Bangcle 找 `libc_malloc`，ijiami 找 `dalvik-DEX`。
- dd 按 4096 页对齐，`bs` 降级 4096→1024→64→1。
- 按 header `file_size` 读取，跨 mmap 分段拼接，空洞补零并记录。
- `freeze_dd` 轮询 maps，SIGSTOP 后 dump，`finally` CONT。

## Evidence 与运行状态

- 所有工具结果内联 Evidence；ID 内容寻址。
- `run.json` 保存阶段、attempts、artifacts、evidence_ids。
- `mutations.json` 保存设备改动及恢复命令。
- `evidence.jsonl` 追加写；重复 ID 相同内容 dedupe，不同内容 integrity_mismatch。
- MCP 响应超过预算时返回 `resource_constraint`，提示 `get_evidence` /
  `export_evidence_bundle`，不静默截断。

## 经验记忆

- `application/memory.py` 维护全局 `lessons.json`（原子写入 + 锁）。
- `dump_android_dex` 在“失败后回退成功”时自动记录失败/成功方法、壳、
  ABI、错误症状、run/evidence 链接。
- `launch_android_target` 在自动模拟器库绕过成功时记录崩溃循环与解法。
- `recommend_unpack_strategy` 召回相关 lesson；重复验证后（2 次重排
  fallback，3 次提升 learned primary）才调整顺序，且永不提升
  `do_not_attempt`。
- 记忆是历史证据，不替代确定性规则、证据校验或授权检查。

## 并发与锁

- MCP 单 worker 顺序执行工具；主线程继续读 stdin 以处理取消通知。
- 每个 run 有 `LOCK` 文件，防止并发修改；600 秒视为陈旧锁。
- CLI 每次命令独立进程，不使用长连接状态。

## 已知边界

- 真机 Frida/dd 链路需要设备；当前环境无设备，相关路径只有离线替身测试。
- 360/Android 版本差异会影响 DexFile 偏移；脚本探测两种偏移并以 magic 校验。
- Bangcle/新版 360 的 inline syscall 无法从用户态稳定绕过；工具会在一次失败后
  转入 dd 或报告真机回退。
# Built-in unpack reference bundle

The web job and chat engines load the built-in skill together with all ten
Markdown files under `references/`. A link in `SKILL.md` alone is not sufficient:
`backend.skill_content.read_skill_bundle` expands the complete bundle. Missing
required references, invalid UTF-8 and a context budget too small for the bundle
fail explicitly. Engine configuration events include the loaded reference paths.

Reference documents use anonymous sample labels in place of concrete APK names
and application package names. Shell class signatures, library names, commands,
case observations and limitations are retained because they determine routing.

Historical lessons are separate from the reference bundle. When migrating a
runtime, transfer verified lessons with their evidence and environment limits;
ABI alone does not establish Android SDK or native bridge compatibility. A
missing process must not be reported as a package mismatch or evidence of a
specific anti-debug mechanism.

Partial bytecode is a deliverable when the target's manifest corroborates its
code namespace and the DEX retains parseable coded classes. The dump chain first
exhausts its permitted fallbacks, then retains incomplete target DEX as
`partial_recovery`; repair, validation and best-effort JADX still run. Structural
completeness remains a separate strict verdict. Holes, repaired signatures and
decompilation errors remain visible, and partial results never promote a method
as a verified lesson. Empty, loader-only and unrelated SDK output cannot satisfy
target recovery. The same policy is shared by native CLI, MCP and web engines.

The ARM64 fallback also depends on the interpreter actually held open by the
kernel. With binfmt_misc's `F` flag, replacing QEMU at the same pathname leaves
the registered handler using its old inode. The deployment refresh helper
re-registers only the ARM64 entry from its existing configuration after a build;
matching the pathname alone is insufficient. Container entry, Android boot,
target startup and recovered business bytecode are separate readiness checks.

The opt-in ARM64 image contains `/apu-binder-compat`. Its matching project QEMU
profile rejects unsupported tagged syscall pointers, so Android can use untagged
heap allocations. This prevents nested Binder scatter/gather pointers reaching
the x86 kernel with ARM64 tags. Binder command parsing also respects zero-length
payloads and packed death-notification records; opaque binder/cookie identities
must retain their values. The profile allows netd's NFLOG, XFRM, NETFILTER and
GENERIC netlink protocols only for the matching little-endian ARM64/x86_64 ABI.
The ARM64 socket adapter also implements integer `SO_MARK` writes and the
64-bit `SO_COOKIE` result. Without `SO_MARK`, netd rejects accepted ADB sockets
after startup even though adbd is listening; this is distinct from TCP
reconnection after `adb root`.

For that profile, the guest's own `/proc/<pid>/task` directory lists guest tasks
from `TaskState.ts_tid`, excluding QEMU helper threads. Other processes' task
directories retain the normal host view. This lets Zygote's pre-fork thread wait
finish while preserving real Android threads. These changes have passed an
Android boot smoke check; APK recovery requires its own runtime evidence.

ADB root preparation reconnects the selected TCP transport after adbd restarts,
then verifies `uid=0` within a bounded retry budget. A transport that stays offline
is reported as `device_unavailable`, separately from a connected non-root device.
It never disconnects other transports or restarts the shared ADB server.

QEMU user-mode processes retain the interpreter argv in their kernel cmdline.
PID selection therefore corroborates an exact ActivityManager process name
with that QEMU wrapper and the matching truncated kernel comm. Native processes
retain their strict cmdline ownership rules. A framework package prefix or a
stale PID with another kernel name cannot establish ownership.
The ARM64 analysis image enables the existing Android USB host framework service;
an empty device list is supported without attaching the host's physical USB bus.
This satisfies applications that enumerate USB devices during startup.

For a launcher outside the install appId, target coverage includes its containing
namespace and at most one parent with three or more segments. This covers
business siblings of a `ui`/`app` entry point without accepting a shared vendor
root. DEX headers found inside a memory region are completed from their own
virtual address and declared file size across readable mappings, subject to the
configured byte cap. Original fragments and any zero-filled holes remain in the
evidence; a longer read never by itself establishes structural completeness.

