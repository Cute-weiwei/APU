# 工具设计

## 先决定是否需要新工具

围绕分析问题设计。先检查现有工具和契约；意图与结果契约一致时扩展现有工具，
只有出现明确不同的结果/权限边界时才新增。

## 工具形态

| 形态 | 用途 | 本项目的例子 |
|---|---|---|
| `inspect` | 一个目标的事实 | `inspect_apk`、`inspect_process_state` |
| `workflow` | 需要组合的重复结果 | `dump_android_dex`、`unpack` |
| `observe` | 运行时行为 | `launch_android_target` |
| `prepare` | 环境前置与可逆改动 | `prepare_android_environment` |
| `cleanup` | 恢复与资源释放 | `cleanup_run` |

命名使用 snake_case（MCP）与 kebab-case（CLI）；两者在
`contracts/tools.py` 与 `cli.py` 中一一对应。

## 契约要求

每个 `ToolSpec` 必须声明：

- `name` / `title` / `description`：描述实际行为、非目标和前提；
- `input_schema`：严格输入、必填字段、`additionalProperties=false`；
- `effects`：是否改目标/会话/文件/设备、是否起进程、是否执行外部代码、
  是否可能丢数据；
- `annotations`：由 effects 派生 readOnly/destructive/idempotent/openWorld；
- `returns_untrusted_content`：APK/设备文本视为不可信数据。

## 结果与错误

- 成功：`content` 文本 + `structuredContent`（Evidence 或运行摘要）。
- 失败：`isError: true`，只有文本，内容是投影后的错误：
  `code / category / message / retryable / remediation / details / partial`。
- 错误在工具边界投影，内部使用类型化 `AnalysisError`。
- 缺失覆盖用 `unknown`/`partial` 表达，不用空数组冒充“没有”。

## 自动执行护栏

- 源 APK 只读；输出默认落在 run 目录。
- 设备改动必须可逆并记录恢复命令；安装 APK 不自动卸载。
- SIGSTOP 必须在 `finally` 和 `cleanup_run` 中配对 CONT。
- 同一失败方法最多重试一次；策略回退链优先。
- 大响应不截断：走 Evidence 引用/导出。

## 验证

- 离线：合成 APK/DEX/maps + fake adb/frida/jadx。
- MCP：initialize/tools/list/tools/call/ping/畸形消息，断言 stdout 只有 JSON-RPC。
- 真机：每个壳至少一个授权样本，验证策略、dump 完整性、cleanup 回滚。
