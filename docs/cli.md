# CLI

入口：

```powershell
$env:PYTHONPATH = "C:\path\to\apk-unpack-agents\src"
python -m apk_unpack <command>
# 或
.\apu.cmd <command>
```

全局选项（每个子命令都可用）：`--json`、`--runs-dir`、`--serial`。

## 命令

### 检查与策略

```powershell
apu inspect-apk target.apk
apu inspect-apk target.apk --run-id run_...
apu inspect-apk target.apk --no-deep-scan
apu strategy run_...
```

### 资产

```powershell
apu extract-assets target.apk
apu extract-assets target.apk --out .\assets --patterns "assets/__UNI__*.wgt" "assets/*.json"
apu extract-assets target.apk --no-wgt
```

### 设备与环境

```powershell
apu device
apu device --serial 127.0.0.1:62001
apu prepare run_... --frida-server .\frida-server
apu prepare run_... --inner-bypass          # 360 + SecNeo
apu prepare run_... --rename-lib libSdkHelper_sdk.so
apu prepare run_... --apk target.apk --allow-install
```

### 启动与进程

```powershell
apu launch run_...
apu launch run_... --activity com.example.MainActivity
apu launch run_... --no-force-stop
apu launch run_... --no-auto-bypass   # 不自动重命名 ijiami 模拟器检测库
apu process-state run_...
apu process-state run_... --pid 1234
```

### 脱壳

```powershell
apu dump-dex run_...
apu dump-dex run_... --method frida_inmemory
apu dump-dex run_... --method frida_mcookie --mode spawn
apu dump-dex run_... --method disk_pull
apu dump-dex run_... --method memory_dd
apu dump-dex run_... --method frida_inmemory_spawn   # spawn + anti-kill
apu dump-dex run_... --method freeze_dd --freeze-timeout-ms 15000 --freeze-poll-ms 80
```

### 修复、验证、反编译

```powershell
apu repair-dex run_...
apu repair-dex run_... --allow-truncated
apu verify-dex run_...
apu verify-dex run_... --jadx
apu decompile run_...
apu decompile run_... --source dex
```

### 经验记忆

```powershell
# 召回与当前壳/设备相关的经验
apu recall-lessons --shell ijiami --device-abi x86_64
apu recall-lessons --query "signal 9" --json
apu recall-lessons --stats --json

# 手工沉淀新坑/新解法（title/scenario/solution 必填）
apu lesson-add `
  --title "ijiami: attach SIGKILL → freeze_dd" `
  --scenario "ARM-only ijiami on x86_64 Houdini; Frida attach killed the target" `
  --root-cause "inline-syscall anti-debug" `
  --solution "poll dalvik-DEX, SIGSTOP, dd, SIGCONT" `
  --shell ijiami --device-abi x86_64 --winning-method freeze_dd `
  --tag anti-frida --tag houdini --confidence analyst --scope global
```

`dump_android_dex` / `launch_android_target` 会自动记录观测到的回退和
模拟器绕过；不需要手工重复。详见 [memory.md](memory.md)。

### Evidence 与收尾

```powershell
apu evidence run_...
apu evidence run_... --id ev_...
apu export-evidence run_... --out .\bundle.json
apu run-state run_... --events
apu cleanup run_...
apu cleanup run_... --delete-run
apu cleanup run_... --prune-raw          # 删除大体积 region_*.bin
```

### 一键流程

```powershell
apu unpack target.apk
apu unpack target.apk --serial 127.0.0.1:62001 --inner-bypass
apu unpack target.apk --install                 # 安装 base + 同包 split
apu unpack target.apk --install --no-jadx
apu unpack target.apk --no-cleanup
apu unpack target.apk --freeze-timeout-ms 20000 --freeze-poll-ms 50
apu unpack target.apk --frida-timeout-ms 120000 --max-region-bytes 134217728
apu unpack target.apk --keep-device-files --no-auto-bypass
```

流程：inspect → strategy → device → prepare → launch → process-state →
dump(auto) → repair → verify(+jadx) → cleanup。`unpack` 默认在结束时执行
设备恢复（SIGCONT、库名、forward、临时文件）；需要保留现场时用
`--no-cleanup`。遇到第一个失败的前置条件即停止，错误里带 `run_id` 与
已完成的 cleanup 摘要。

### 诊断与安装

```powershell
apu doctor
apu setup --project-dir .                    # 预览
apu setup --project-dir . --yes              # 应用
apu setup --project-dir . --yes --uninstall
apu setup --client generic                   # 输出可粘贴配置
apu mcp                                      # stdio server
```

## 退出码

| 码 | 含义 |
|---|---|
| 0 | 成功或仅预览 |
| 1 | 工具错误（JSON 错误投影） |
| 2 | 参数错误（argparse） |
| 130 | Ctrl+C |

## JSON

`--json` 输出完整结果（含 Evidence）。默认输出摘要；错误默认写 stderr，
`--json` 时写 stdout。
