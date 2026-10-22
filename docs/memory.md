# 经验记忆（Lessons）

## 目标

把每次脱壳发现的新场景、新坑、有效解法沉淀为可检索的历史证据，让后续
策略更贴合当前壳/ABI/设备，同时不被一次偶然观测带偏。

## 数据位置与格式

- 默认 `%LOCALAPPDATA%\apk-unpack\memory\lessons.json`
- `APU_MEMORY_DIR` 可覆盖；与 `runs/` 分离
- 原子写入 + `LOCK`；损坏时报 `integrity_mismatch`，不静默覆盖
- 每条 lesson 关键字段：

```json
{
  "lesson_id": "ls_<sha256>",
  "fingerprint": "...",
  "kind": "auto|manual",
  "title": "...",
  "scenario": "...",
  "shell": "ijiami",
  "device_abi": "x86_64",
  "apk_abi_class": "arm-only",
  "framework": null,
  "package_scope": "global",
  "symptoms": [],
  "root_cause": "...",
  "solution": "...",
  "winning_method": "freeze_dd",
  "failed_methods": [{"method": "frida_inmemory", "code": "execution_failure", "message": "signal 9"}],
  "tags": ["auto", "dump"],
  "evidence_links": ["run:run_...", "ev:ev_..."],
  "examples": [{"run_id": "...", "package": "...", "evidence_id": "...", "timestamp": "..."}],
  "confidence": "observed|analyst",
  "occurrences": 1,
  "success_count": 1,
  "created_at": "...",
  "updated_at": "...",
  "last_seen": "...",
  "limitations": []
}
```

## 自动沉淀

`dump_android_dex` 在“自动策略有失败、最终回退成功”时记录：

- 失败方法、错误码/消息/关键 captured output
- 成功方法
- 壳、设备 ABI、APK ABI 类别、框架
- `run:...` / `ev:...` 链接与一个 example

`launch_android_target` 在触发自动模拟器库绕过并成功启动时记录：
崩溃循环症状、根因、可逆重命名解法、目标包 example。

自动 lesson 的指纹不包含包名，默认全局复用；包名只进 `examples`。
同一指纹重复出现时合并并增加 `occurrences/success_count`。

## 手工沉淀

MCP `remember_unpack_lesson` / CLI `lesson-add`：

- 必填 `title/scenario/solution`
- 建议提供 `root_cause`、`symptoms`、`winning_method`、`failed_methods`、
  `tags`、`evidence_links`
- `scope=package` 时只对指定包生效；默认 `global`
- 手工 lesson 的 `confidence=analyst`，合并时会覆盖同指纹的 auto 文本

## 召回与学习阈值

`recall_unpack_lessons` 按 shell、设备 ABI、APK ABI、框架、包级 scope、
query、tags、出现次数、成功率、最近 30 天排序，并返回
`score/relevance_reasons`。

`recommend_unpack_strategy` 自动召回前 8 条：

- `occurrences >= 2` 且成功率 ≥ 60%：成功方法提前到 fallback 首位
- `occurrences >= 3` 且成功率 ≥ 80%，且当前 primary 在失败方法中：
  设置 `learned_primary`，`dump_android_dex(method=auto)` 会先试它
- `do_not_attempt` 永不提升
- 每次调整记录在 `learned_adjustments`（lesson_id、次数、成功率、原因）

## 隐私与安全

- 所有文本经过常见 token/secret/password/authorization/api-key 模式脱敏
- 不存储 APK 字节；`examples` 可能包含包名，可按需手工清理
- 不存储设备序列号作为指纹；只存 ABI/SDK 类信息
- lesson 是历史证据，不是授权，也不能覆盖 `do_not_attempt` 或证据校验

## 运维

```powershell
python -m apk_unpack recall-lessons --shell ijiami --device-abi x86_64 --json
python -m apk_unpack recall-lessons --stats --json
python -m apk_unpack recall-lessons --query "signal 9" --json
python -m apk_unpack lesson-add --title "..." --scenario "..." --solution "..."
```

需要重置时先备份 `lessons.json`；不要直接删除目录后假设历史不存在。
