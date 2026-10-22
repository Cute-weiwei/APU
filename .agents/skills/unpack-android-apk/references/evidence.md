# Evidence、运行目录与清理

## Evidence 记录

每条记录包含：

```json
{
  "evidence_id": "ev_<sha256>",
  "subject": {"format": "apk", "sha256": "...", "size": 123},
  "provider": {"id": "apk-static", "name": "...", "version": "0.1.0"},
  "predicate_type": "apk.static",
  "operation": "inspect_apk",
  "parameters": {},
  "normalized_result": {},
  "confidence": "observed | derived | inferred",
  "authority": "shipped-artifact | live-device | controlled-replay | historical-reference | analyst-inference",
  "environment": {},
  "limitations": [],
  "locations": [],
  "evidence_links": []
}
```

- `evidence_id` 由规范化 JSON（排除 `evidence_id`、`subject.name`、`subject.local_path`）
  的 SHA-256 生成；移动文件不改变身份。
- 同一 ID 相同内容 → duplicate；相同 ID 不同内容 → `integrity_mismatch`。
- 大文件不进入 Evidence，只记录路径 + SHA-256。
- 缺失覆盖是 `unknown`，不是“没有”。

## 运行目录

```
<runs>/<run_id>/
  run.json
  evidence.jsonl
  events.jsonl
  mutations.json
  dexdump/raw/
  dexdump/fixed/
  dexdump/jadx/
  assets/
  tmp/
  logs/
  LOCK
```

默认 `<runs>`：

- Windows：`%LOCALAPPDATA%\apk-unpack\runs`
- 其他：`~/.local/share/apk-unpack/runs`

可用 `APU_RUNS_DIR`、`APU_HOME` 或 CLI `--runs-dir` 覆盖。

## 设备改动（mutations）

| kind | 可逆 | 恢复方式 |
|---|---|---|
| `rename_device_lib` | 是 | `.apu.bak` 改回原名 |
| `kill_stop` | 是 | `kill -CONT` |
| `frida_server_start` | 是 | kill 本次启动的 PID |
| `adb_forward` | 是 | `adb forward --remove tcp:<port>` |
| `push_file` | 是（若为本次创建） | 删除 push 的文件 |
| `install_apk` | 否 | 保留，需手工卸载 |
| `force_stop` | 否 | 只记录时间线 |

## 清理流程

`cleanup_run`：

1. 逆序处理 mutations；
2. 对已 STOP 的进程发 CONT；
3. 恢复 `.apu.bak`；
4. 移除本次 forward；
5. kill 本次 frida-server；
6. 删除 `/data/local/tmp/apu/<run_id>` 与 App `files/apu/<run_id>`；
7. 若全部成功且 `delete_run=true`，删除运行目录；否则保留并返回
   `cleanup_incomplete`。

## 报告模板

```
run: run_...
target: <package> / <sha256>
shell: <primary> (layers: ...)
route: <method> (attempts: ...)
artifacts:
  dexdump/fixed/classes.dex  size=... classes=... sha256=...
verification: complete|partial (checks: ...)
known unknowns: ...
device mutations: 12 applied / 12 restored
cleanup: complete
```

只报告实际执行过的事实。静态推断、未连接设备的策略、未验证的 Frida 路径都要
明确标注为 inferred/unverified。

## 部分产物的容忍与交付

安装包名（applicationId）不一定等于业务类命名空间。验证应同时使用包名和
Manifest 启动 Activity 所属命名空间；不得用任意 SDK 类证明已恢复目标业务。

允许 JADX 存在方法重建错误、缺失字节或反编译警告。有可解析、包含代码的目标
DEX 时，保留原始文件、修复文件和可恢复的 Java；尝试完允许的回退后可返回
`partial_recovery`，继续 repair / verify / JADX，不要求百分之百还原。该结果必须
报告 `complete=false`、缺损原因及 JADX 实际输出数量，不得计为完整恢复的成功
经验。纯壳、无代码文件、无目标业务和启动失败不能用容忍度掩盖。
