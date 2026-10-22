# 功能完整性审计（2026-10-18）

审计范围：全部 `src/apk_unpack`、CLI/MCP 契约、Skill/references、测试，以及 ChatCube / 2.apk 两次真实设备运行的失败与成功路径。
方法：对照 12 篇 `zhishi*.md` 实战知识 + 逐条代码路径核对 + 真机证据。

结论：**存在功能性遗漏**。核心链路可用（ijiami 两个 APK 已真实脱壳成功），但有 6 项 P0 会阻断“一键”流程或给错回退策略。

## 修复状态（2026-10-18）

已修复并通过 57 项测试 + 真机验证：

- **P0-1**：`unpack --install`、未安装预检、ABI 兼容检查、base + split `install-multiple`；`.apks`/`.xapk` 可通过 `prepare --apk --allow-install` 安装。
- **P0-2**：Bangcle 回退改为 `memory_dd_retry`；freeze 谓词按壳泛化（Bangcle 等 `libc_malloc/[heap]`）。
- **P0-3**：新增 `frida_inmemory_spawn`（spawn + anti-kill）回退。
- **P0-4**：`pidof` 为空时回退 `ps -A`，支持隐藏/截断进程名。
- **P0-5**：freeze 轮询中检测 PID 存活并重新查找/重启，最多重试。
- **P0-6**：`memory_dd` 不再把“只有 truncated 候选”当成功，会触发 fallback。
- **P1-10/11/14/15**：ABI 预检查、`freeze_poll_ms` 生效、主机 Frida 临时目录清理、`cleanup --prune-raw`、更多 mCookie 偏移探测。
- **P2**：安装错误分类、`launch` 未安装预检、`unpack` 暴露 freeze/frida/region/keep/auto-bypass 选项。

仍然保留的限制：

- P1-7：split sibling 安装已支持；`.apks`/`.xapk` 的直接 inspect/完整 bundle 合并仍未实现（会给出明确错误）。
- P1-8：Flutter/React Native 只检测，不提取 `libapp.so` / `index.android.bundle` 业务逻辑。
- P1-9：非 root / `run-as` 路径仍未实现。
- P1-12：`enumerate.js` 仍未暴露为工具（类名-only 兜底）。
- P1-13：MCP 取消仍只覆盖 dump，JADX/verify 长任务不可取消。
- 真机覆盖仍以 ijiami 为主；Bangcle/360/Tencent MTP/split/非 root 待补样本。

---

## P0 — 影响主流程/策略正确性

### 1. `unpack` 不会安装目标 APK

- `application/workflow.py` 的 `unpack()` 调用 `prepare_android_environment(..., allow_install=False)`，随后 `launch_android_target(...)` 也没有 `install=True`。
- 影响：对一个尚未安装的新 APK 执行 `apu unpack target.apk` 会在 launch 阶段失败；真实测试中 ChatCube 和 2.apk 都是**手工 `adb install`** 后才能跑。
- 修复建议：`unpack` 增加 `install: bool = False` 与 `apk_path`，CLI 增加 `--install`；安装走 `prepare` 并记录不可逆 mutation。
- 规模：S。

### 2. Bangcle 的 `freeze_dd` 回退是死路

- `application/strategy.py` Bangcle 分支 `fallbacks = ["freeze_dd"]`。
- `application/workflow.py` freeze 模式的等待条件固定为：
  `"dalvik-dex" in path and size > 1MiB`。
- 但 Bangcle 的 DEX 在 `libc_malloc`/`[heap]`，不会出现 `dalvik-DEX`。
- 影响：`memory_dd` 首次错过崩溃窗口后，Agent 会进入一个永远等不到目标的 freeze，最终 dump 失败。
- 修复建议：Bangcle 回退改为“重新启动 + fast memory_dd 重试”，或把 freeze 谓词按壳泛化（Bangcle 等 `libc_malloc` + DEX magic/延迟冻结）。
- 规模：M。

### 3. ijiami 没有 spawn + anti-kill 回退

- `strategy.py` ijiami 分支回退只有 `memory_dd`、`freeze_dd`。
- `workflow.py` 中 `anti_kill=True` 只接在 `frida_mcookie_spawn`（360）上；`preamble.js` 的 anti-kill hook 对 ijiami 没有被使用。
- 知识库 `zhishi7.md`（yy.apk）明确记录：attach 被 SIGKILL 后，spawn + anti-kill + `NativeFunction(fwrite)` 成功。
- 影响：真实 ChatCube 的 attach 失败后 Agent 直接转 dd，少了一次文档验证过的 Frida 回退。
- 修复建议：增加 `frida_inmemory_spawn`（spawn + anti_kill）回退，放在 memory_dd 前；Bangcle 的 `do_not_attempt` 仍需排除。
- 规模：S/M。

### 4. `find_pid` 在 `pidof` 为空时不会回退 `ps -A`

- `providers/process.py` `find_pid()` 先 `pidof`，为空立即抛 `process_not_running`；只有“多个 PID”时才执行 `ps -A`。
- 影响：ijiami 等会隐藏进程/进程名的壳，`pidof` 可能为空，Agent 会误报进程未运行。
- 修复建议：`pidof` 为空时也执行 `ps -A -o PID,PPID,NAME,ARGS`，按包名/args 匹配。
- 规模：S。

### 5. freeze 只盯初始 PID，不处理崩溃循环换 PID

- `workflow.py` freeze 分支在 launch 后拿一次 PID，随后 `wait_for_map` 一直用这个 PID。
- 真实 2.apk 测试出现过一次 `no dalvik-DEX region appeared within 5000 ms`；当前已放宽到 15s 并加主动模拟器绕过，但**仍没有在 PID 死亡后重新找 PID/重试**。
- 影响：自毁/崩溃循环类 App 的短窗口可能被漏掉。
- 修复建议：轮询中检测 PID 存活；死亡则重新 `find_pid`（或重新 launch），最多重试 1–2 次。
- 规模：M。

### 6. `memory_dd` 把“只有截断候选”当成功

- `workflow.py` `_attempt_memory()` 只在 `if not candidates` 时抛错；没有要求至少一个 `complete=True` 的候选。
- 影响：dump 阶段报成功，但 `repair` 会跳过 truncated DEX，`verify` 失败；auto 策略不会触发下一个回退。
- 修复建议：若所有候选都 truncated，继续扫描其他区域，最终仍不完整则抛 `dump_incomplete` 触发 fallback。
- 规模：S。

---

## P1 — 重要能力覆盖

| # | 遗漏 | 证据/影响 | 规模 |
|---|---|---|---|
| 7 | Split APK / App Bundle / `.apks` / `.xapk` 不支持 | 只有 `split_apk` 提示；无 `install-multiple`；base split 单独安装会缺资源/ABI | L |
| 8 | Flutter / React Native 只检测不提取 | 业务逻辑在 `libapp.so` / `index.android.bundle`；DEX dump 拿不到（已在 references 标注） | M/L |
| 9 | 非 root / `run-as` 路径未实现 | `prepare` 总是 `ensure_root`；MTP 磁盘 pull 依赖 root；`run-as` 只在注释里 | M |
| 10 | 安装前无 ABI 兼容检查 | ARM-only APK 装到无 ARM 翻译的设备会得到泛化 install 错误，无专门 remediation | S |
| 11 | `freeze_poll_ms` 参数未生效 | 契约和函数签名有该参数，实际 `wait_for_map(interval_ms=80)` 硬编码 | S |
| 12 | `enumerate.js` 未被任何工具使用 | 没有“cookie 失败时只导出类名”的兜底 | S/M |
| 13 | MCP 取消只对 dump 生效 | `decompile`/`verify --jadx` 没有 cancel 传递，长任务无法中止 | M |
| 14 | 主机侧 Frida wrapper 临时目录未清理 | `%TEMP%/apu/<run>` 累积；raw `region_*.bin` 也长期保留 | S |
| 15 | 360 Android 10+ mCookie 偏移只探测两种 | 其他布局会报 unknown；文档已声明，但仍是覆盖缺口 | M |

---

## P2 — 易用性 / 运维

- `unpack` 未暴露 `--install`、`--freeze-timeout-ms`、`--frida-timeout-ms`、`--max-region-bytes`、`--keep-device-files`、`--no-auto-bypass`。
- install 错误未区分签名冲突/空间不足/ABI；launch “未安装” 会落到 `process_died`，而不是明确的 `not_found/not_installed`。
- 真机覆盖目前只有 ijiami（ChatCube、2.apk）；Bangcle/360/Tencent MTP/非 root/split 未做真机验证。
- 无 `--keep-raw`/prune 选项；单次 Bangcle 大区 dump 可能产生数百 MB `.bin`。
- 经验记忆只记录“成功回退/绕过”，不记录持续失败；精确失败链指纹会让波动场景产生多条 lesson（这是有意的反过拟合设计，但需要文档化/调优）。
- README 的“Frida/内存 dump 真机链路待验证”已过时（ijiami 已真机验证）；建议更新状态与覆盖矩阵。

---

## 已经可用、不算遗漏

- 静态检测：ZIP 签名、AXML/aapt、DEX header、壳优先级、ABI/框架识别、资产/wgt 提取。
- 策略：通用决策树 + lesson 增强 + learned_primary + `do_not_attempt` 保护。
- 运行时：Frida cookie/in-memory/mCookie、磁盘 pull、memory dd、freeze dd、主动/自动模拟器库绕过。
- 产物：DEX 修复/去重/命名、checksum/signature/class 表验证、JADX 反编译与错误统计。
- 工程化：Evidence 账本、run/mutation、cleanup、CLI/MCP、Skill、经验记忆、48 项离线测试。
- 真实结果：ChatCube 4 DEX / 21,739 类；2.apk 5 DEX / 34,470 类；记忆成功把 `memory_dd` 提升为 learned primary。

---

## 建议修复顺序

1. **P0**：`unpack --install`、ijiami spawn+anti-kill、`find_pid` ps 回退、memory_dd 完整性判断。
2. **P0**：Bangcle 回退重设计、freeze PID 重找/重试。
3. **P1**：`freeze_poll_ms`、ABI 预检查、主机临时目录清理、MCP 取消、类名 fallback。
4. **P2**：split/Flutter/RN/非 root（按产品范围决定是否投入）。
