# DEX 修复、去重与验证

## Header 布局

| 偏移 | 字段 |
|---|---|
| 0x00 | magic `dex\n035\0` / `037` / `038` / `039` |
| 0x08 | checksum（Adler32 over `[0x0C:]`） |
| 0x0C | signature（SHA-1 over `[0x20:]`，20 字节） |
| 0x20 | file_size |
| 0x24 | header_size（标准 0x70） |
| 0x28 | endian_tag（0x12345678） |
| 0x38 | string_ids_size |
| 0x3C | string_ids_off |
| 0x40 | type_ids_size |
| 0x44 | type_ids_off |
| 0x60 | class_defs_size |
| 0x64 | class_defs_off |
| 0x68 | data_size |
| 0x6C | data_off |

`cdex001\0` 是 compact dex（系统 jar 常见），不是应用 DEX；默认跳过。

## 修复顺序（严格）

1. 确定权威长度：
   - `file_size <= 实际长度` → 截断到 `file_size`；
   - `file_size > 实际长度` → 截断 dump；默认拒绝，`allow_truncated=true`
     时把 `file_size` 改为实际长度并标记 truncated；
   - `file_size` 不合理 → 使用实际长度。
2. 写入新的 `file_size`。
3. 清零 `checksum[0x08:0x0C]` 与 `signature[0x0C:0x20]`。
4. 计算 `SHA-1(data[0x20:])` 写入 `0x0C`。
5. 计算 `Adler32(data[0x0C:])` 写入 `0x08`。

顺序不能乱；否则 checksum 必然不匹配。大文件使用流式读写，避免整文件进内存。

## 验证

逐文件：

- magic/version、header_size=0x70、endian=0x12345678；
- `file_size == 实际大小`；
- Adler32 与 SHA-1 与 header 一致；
- `class_defs_size > 0`；
- class_defs 表可遍历，`class_idx` / `type_idx` / `string_idx` 边界有效；
- 统计 `L<package>/` 开头的描述符数量；
- 可选 JADX：统计 `.java` 文件数。

`complete` 只有在所有候选完整提取、header 可解析、class 表可遍历、校验通过时才成立。

## 去重与命名

- 精确去重：完整 SHA-256。
- 近似去重：`(file_size, class_defs_size, SHA-256(前4KiB))`。
- 保留校验通过或最先出现的候选，其他列为 duplicates。
- 排序：size 降序 → class_defs 降序 → SHA-256 升序。
- 命名：`classes.dex`、`classes2.dex`、……。
- 默认排除 `class_defs_size <= 10` 的壳 stub；若只有 stub 则保留并注明。
- 输出 `manifest.json`，记录源文件、地址、原始大小、hash。

## 完整性启发式

| 指标 | 参考 |
|---|---|
| DEX 数量 | 通常 3–12 个 |
| 最大 DEX | > 5 MiB |
| 总大小 | > 10 MiB |
| class_defs 总量 | > 500（真实应用常数千到数万） |
| jadx Java 文件 | > 5000 |
| 包名类 | > 50–100 |
| 真实 Application | 能找到 `extends ... Application` |
| Launch Activity | 能找到 manifest 中的启动页 |

参考案例：样本01 36,488 类；样本02 38,841 类；样本03 68,386 类；样本04 38,685 类。
这些数字只作量级参考，不是绝对值。

## 常见失败

默认 JADX 发生重建错误时，工具会在剩余预算内导出失败类的 fallback 原始指令视图，
源码 ZIP 中见 `recovery/fallback/`。它可用于阅读正常 Java 未能重建的方法，
不能当作可编译源码，也不改变主输出的 `partial` 状态。

JADX 默认时限为 3600 秒（`APU_JADX_TIMEOUT_S` 可覆盖）；CLI `decompile --timeout`
或 `unpack --jadx-timeout-s` 可按任务设置。先查看结果的 `timed_out` 和 `duration_s`，
不要把控制流重建异常当作超时。`incomplete_file_count` 统计含警告的 Java 文件数，
不能当作失败方法数计算比例。DEX 校验和源码重建质量应分别报告。

| 现象 | 原因 |
|---|---|
| jadx “No classes” | DEX 截断/跨 mmap 未完整 |
| checksum 不匹配 | 修复顺序错误，或改动了 `0x0C` 之后的数据 |
| 只有壳类 | 只拿到了 stub，真实 DEX 未 dump |
| 类数远低于预期 | 漏 cookie/漏区域/去重误删 |
| 大量零字节 | dump 到全零区域 |
| jadx 缓存旧结果 | 清理 `%LOCALAPPDATA%\skylot\jadx\cache` 后重试 |
