# 内存 dump（/proc/pid/mem）与冻结

## PID 选择

1. `pidof <package>`。
2. 多个 PID：用 `ps -A -o PID,PPID,NAME,ARGS`，优先 `NAME == package`；
   跳过 `package:remote`，除非只有它存在。
3. 短命进程：启动后每 80ms 轮询，最长 5s。
4. 读取 `/proc/<pid>/status` 记录 `TracerPid`、`State`、`Threads`。

双进程 ptrace 保护：守护进程 fork 后 ptrace 主进程；按 `PPID=zygote` 找主进程，
不要按进程名猜。

## maps 解析

```
start-end perms offset dev inode pathname
```

路径可能含空格：`/dev/ashmem/dalvik-DEX data (deleted)`。必须保留整行尾部，
不要只取最后一个字段。

## 区域评分（启发式）

| 区域 | 分数 |
|---|---|
| `dalvik-DEX` / `dalvik-DEX data` | +100 |
| `libc_malloc` | +50 |
| `[heap]` | +30 |
| `dalvik-main space` | +25 |
| `anon:Mem_*` | +20 |
| 其他 rw 匿名 | +15 |
| 10–80 MiB | +20；5–10 MiB +10；>100 MiB +5 |
| stack/vvar/vdso/cfi shadow | -100 |
| gralloc | -50 |
| 非 rw 且非 dalvik-DEX | -40 |

- Bangcle：优先 `libc_malloc` / `[heap]`。
- ijiami：优先 `dalvik-DEX`；若 header 在区域起始处可直接按 `file_size` 读。
- 未知壳：按分数从高到低尝试前 4 个区域。

## dd 数学

目标 `[start, end)`：

```
page = 4096
aligned = start & ~(page - 1)
prefix  = start - aligned
pages   = ceil((prefix + size) / page)
skip    = aligned // bs
count   = ceil(chunk_len / bs)
```

- 每块最多 8 MiB。
- `bs` 降级：`4096 → 1024 → 64 → 1`；`bs=1` 只用于 ≤1 MiB 的失败范围。
- x86_64 的 `/proc/pid/mem` 可能不支持页块 lseek，`bs=4096` 会 I/O error；
  `bs=1024` 或 `bs=1` 是必要回退。
- `dd` 的 I/O error 可能是地址空洞；已读到的数据仍然有效。

## 跨 mmap 完整 dump

1. 先读 112 字节 header，解析 `file_size@0x20`。
2. 校验 `0x70 <= file_size <= 512MiB`。
3. 按 `file_size` 读取，不要按 map 大小。
4. 按 maps 把范围切成可读段；空洞补零并记录。
5. 只有每个字节都读到、且修复后 checksum 通过，才标记 complete。
6. 否则标记 truncated；jadx 可能报 “No classes”。

同一 mmap 内可以嵌入多个 DEX。对区域中间扫描出的有效 header，也必须以该
header 的虚拟地址和 `file_size` 跨映射补读；不能只对区域首部的 DEX 这样做。
补读受字节上限和取消信号约束，原始片段、空洞和新读取结果均保留。

映射首部没有 magic 也不能直接跳过：保护属性切换会把同一分配切成多个
`dalvik-DEX` 段，下一份 DEX 的头可能在延续段中间。仍按上限扫描，再跨映射补读。

完整性检查失败但有实际业务类及代码时，保留 `partial` 产物并继续 JADX；显式
`memory_dd` 与自动模式采用同一规则。同次匿名 DEX 抓取的可解析依赖库可随业务
DEX 保留，但依赖库不能单独证明脱壳成功。JADX 的局部错误、零填充范围和缺失
方法必须保留说明；不要求百分百源码还原，也不把部分结果提升为完整成功经验。

同一任务的部分内存快照可能只因方法字节变化而产生不同 checksum。修复时只有在
已有本次动态抓取证据、文件均来自该 run 的 raw 目录，且类表、完整类名和归一化
前部一致时，才选择代码更多、空洞更少的版本；不拼接方法字节，全部原始版本保留。
不同类名的 DEX 不归为同一版本。重复修复只清除上次 manifest 记录且哈希一致的
多余输出，不能删除目录里的其他文件。

已知案例：10.5MB DEX 落在 9.2MB 的 mmap 里，按区域大小截断会失败。

## 自毁型 App 冻结

1. `am force-stop`，再 `am start`。
2. 按壳选择冻结目标（`freeze_poll_ms` 可调，默认 80ms）：
   - ijiami：`dalvik-DEX`（>1MiB）
   - Bangcle：`libc_malloc` / `[heap]`（>4MiB）
   - 未知：任意可写区（>1MiB）
3. 一出现立即 `kill -STOP <pid>`。
4. 轮询期间若 PID 死亡（崩溃循环换 PID），重新查找或重启进程，最多重试。
5. 确认 `State: T`；若没有，`kill -CONT` 后重试。
6. 冻结后从容 dump；`memory_dd` 若只有 truncated 候选会继续 fallback。
7. `finally` 和 `cleanup_run` 都必须 `kill -CONT`。

冻结期间进程可能被 Android 终止。SIGCONT 失败后，只有设备端命令成功确认
`/proc/<pid>` 已不存在，才可记录无需恢复并继续保留已读产物；ADB 断连仍属清理失败。

解密完成时间会抖动（约 0.24–1.8s），固定 sleep 不可靠。

## 零字节检查

- 采样前 64KiB；若 ≥99.5% 为零，跳过该区域。
- `anon:Mem_*` 预分配区可能全零。
- 扫完一个区域后，仍应检查其他高分区域，避免漏 DEX。

## 设备临时文件

- 默认设备目录：`/data/local/tmp/apu/<run_id>/`。
- `cleanup_run` 会删除；`keep_device_files=true` 可保留。
- 每个 dump 区域/分块记录 `bs`、地址、是否空洞，便于复盘。
