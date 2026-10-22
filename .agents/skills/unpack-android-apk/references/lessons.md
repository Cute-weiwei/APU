# 持久化经验记忆（Lessons）

目标：每次脱壳发现的新场景、新坑、有效解法都沉淀下来，下次遇到同类
App/设备/壳时自动召回，让 Agent 越用越准。

## 存储位置

- 默认：`%LOCALAPPDATA%\apk-unpack\memory\lessons.json`
- 覆盖：`APU_MEMORY_DIR`
- 结构：`{"schema_version":1,"updated_at":...,"lessons":[...]}`
- 写入是原子的（`.tmp` + `os.replace`），并有 `LOCK` 防止并发覆盖。
- 记忆目录与运行目录分离；删除某次 run 不会删除经验。

## 记录什么

优先记录“可复用”的事实，而不是单次流水：

- 新壳/新变种的文件、manifest、DEX 字符串特征。
- 新的反调试/反模拟器行为 + 实际有效的绕过。
- 在特定壳/ABI/设备上，某个 dump 方法失败、另一个成功。
- 清理/恢复、设备路径、JADX/Frida 版本相关的坑。
- 只在特定包成立的结论请用 `scope=package`，不要污染全局。

不要记录：账号/token/密码、APK 字节、无关用户数据、没有证据的猜测。

## 自动记录

以下路径会自动写入 `kind=auto` 的 lesson：

1. `dump_android_dex`：如果自动策略先失败、后回退成功，会记录
   失败方法、错误码/信息、成功方法、壳、设备 ABI、APK ABI 类别、
   `run:...` / `ev:...` 链接。
2. `launch_android_target`：如果应用因模拟器检测崩溃循环，Agent 自动
   重命名 `libijm-emulator.so` / `libijmdetect-drisk.so` 后成功启动，
   会记录该绕过。

自动 lesson 的指纹不包含包名，默认全局复用；具体案例放在 `examples`
里（最多 10 条），方便追溯但不会限制适用范围。

## 手工记录

用 MCP `remember_unpack_lesson` 或 CLI：

```powershell
python -m apk_unpack lesson-add `
  --title "ijiami: attach SIGKILL → freeze_dd" `
  --scenario "ARM-only ijiami on x86_64 Houdini; Frida attach killed the target" `
  --root-cause "inline-syscall anti-debug" `
  --solution "poll dalvik-DEX, SIGSTOP, dd, SIGCONT" `
  --shell ijiami --device-abi x86_64 --winning-method freeze_dd `
  --tag anti-frida --tag houdini --confidence analyst --scope global
```

手工 lesson 必须提供 `title/scenario/solution`；同一 `title` + `scope` +
`shell` 会合并而不是重复。新的 analyst 文本会覆盖同一指纹下的 auto 文本。

## 召回与排序

`recall_unpack_lessons` 按以下信号排序：

- shell 精确匹配、设备 ABI、APK ABI 类别（arm-only/x86/mixed）、框架
- 包级 scope 精确匹配
- query token、tags 重叠
- 出现次数、成功率、最近 30 天

返回每条 lesson 的 `score` 与 `relevance_reasons`。`recommend_unpack_strategy`
会把前 8 条摘要放进 `strategy.lessons`，并可能产生
`learned_adjustments`。

## 学习阈值（防止一次偶然污染）

- `occurrences >= 2` 且成功率 ≥ 60%：把成功方法提前到 fallback 首位。
- `occurrences >= 3` 且成功率 ≥ 80%，且当前 primary 在失败方法中：
  设置 `learned_primary`，`dump_android_dex(method=auto)` 会先试它。
- 永远不把 `do_not_attempt` 里的方法提升（例如 360 的 `memory_dd`、
  Bangcle 的 Frida）。
- 每次调整都在 `learned_adjustments` 里写明 lesson_id、次数、成功率。

## 查看与排查

```powershell
python -m apk_unpack recall-lessons --shell ijiami --device-abi x86_64 --json
python -m apk_unpack recall-lessons --stats --json
python -m apk_unpack recall-lessons --query "signal 9" --json
```

如果记忆文件损坏，工具会报 `integrity_mismatch` 而不是静默覆盖。
需要重置时手动备份/删除 `lessons.json`；不要删除整个记忆目录后再让
Agent 误以为历史经验不存在。

## 已知边界

- 自动 lesson 只反映一次观测；它的 `limitations` 会明确写出来。
- 包名、设备序列号等敏感信息不会进入自动指纹；`examples` 可能包含包名，
  如不需要请手工编辑。
- 记忆不能替代 `do_not_attempt`、授权检查或证据校验。
