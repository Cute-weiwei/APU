# APK Unpack Agents

REA 风格的 Android APK 脱壳 Agent：**CLI + MCP stdio server + Agent Skill + Evidence 账本**。零第三方 Python 依赖，直接复用本机已有的 `adb`、`frida`、`aapt`、`jadx`。

它把 `zhishi*.md` 里 12 篇实战结论编码成可执行流程，覆盖：

- 爱加密 ijiami（InMemoryDexFile / dalvik-DEX / 自毁冻结）
- 梆梆 Bangcle（libc_malloc dd，绕过 Frida 免疫）
- 360 加固（mCookie 多指针、360+SecNeo 双层）
- 腾讯 MTP（磁盘 prodexdir 直接 pull）
- 混合/双层壳优先级与误判护栏

以及**持久化经验记忆**：

- `dump_android_dex` 自动记录“哪些方法失败、哪个回退成功”。
- `launch_android_target` 自动记录模拟器检测崩溃循环与可逆库绕过。
- 后台每个任务结束都会自动生成/合并经验，但只记录真正有价值的路线：成功且实际产出 DEX/源码、失败但识别出可复用坑位、以及静态直读优化；相同路线按稳定 route key 去重，不会因错误码/文案不同产生重复经验，见 `backend/README.md`。
- 新场景/新坑可用 `remember_unpack_lesson` 手工沉淀。
- 下次按壳、设备 ABI、APK ABI、框架召回；重复验证后才调整策略，
  一次成功不会污染全局规则。

以及安装与稳健回退：

- `unpack --install` 一键安装 base + 同包 split APK（`install-multiple`）；
  `.apks`/`.xapk` 可通过 `prepare --apk bundle --allow-install` 安装。
- Bangcle 使用 `memory_dd_retry` + 泛化 freeze；ijiami 增加 spawn+anti-kill；
  freeze 在崩溃循环换 PID 时会重新查找/重试。

> 仅用于你已获得授权的自有或测试 APK。见 [DISCLAIMER.md](DISCLAIMER.md)。

## 发行方式

当前公开版本保留统一源码入口：CLI / MCP 使用 `src/`，Web 后台使用 `backend/`；Linux Docker 部署使用 [`backend/docker-compose.yml`](../backend/docker-compose.yml)。

## 快速开始

```powershell
cd E:\apk\通用apk破解准备\apk-unpack-agents

# 1) 体检（不会改设备）
.\apu.cmd doctor

# 2) 静态检查 + 壳识别
.\apu.cmd inspect-apk .\target.apk --json

# 3) 查看推荐策略（不执行）
.\apu.cmd strategy <run_id>

# 4) 全自动：安装 → 环境 → 启动 → 进程侦察 → dump → 修复 → 验证 → 自动清理
.\apu.cmd unpack .\target.apk --install
# 已安装的目标：
.\apu.cmd unpack .\target.apk
# 需要保留现场时：
.\apu.cmd unpack .\target.apk --install --no-cleanup

# 单独运行时收尾：SIGCONT、恢复库名、移除 forward/临时文件
.\apu.cmd cleanup <run_id>

# 5) 查看 Agent 从历史运行学到的经验
.\apu.cmd recall-lessons --shell ijiami --device-abi x86_64
.\apu.cmd recall-lessons --stats
```

也可以不经过 `.cmd`：

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m apk_unpack inspect-apk .\target.apk
```

## 安装为 Agent

```powershell
# 只预览改动（默认行为）
python -m apk_unpack setup --project-dir .

# 确认后应用：复制 skill 到 ~/.claude/skills，并合并项目 .mcp.json
python -m apk_unpack setup --project-dir . --yes

# 卸载（只删除本工具记录的条目）
python -m apk_unpack setup --project-dir . --yes --uninstall
```

通用客户端用 `--client generic` 输出可直接粘贴的 MCP 配置。

## 架构

```
domain       Result / AnalysisError / Evidence / RunWorkspace / models
contracts    ToolSpec 目录（CLI 与 MCP 共用）
application  strategy 决策树 + workflow 全部工具实现 + memory 经验库
providers    apk / axml / adb / process / memory / frida / dex / jadx
cli + mcp    argparse CLI 与零依赖 JSON-RPC stdio server
skill        .agents/skills/unpack-android-apk/（SKILL.md + references）
```

依赖方向严格为 `domain → contracts → application/providers → CLI/MCP`。

## Evidence 与运行目录

每次运行创建 `run_YYYYMMDDTHHMMSSZ_<hex>/`：

```
run.json          运行状态、阶段、attempts、artifacts
evidence.jsonl    内容寻址的 ev_<sha256> 证据账本（去重 + 冲突检测）
events.jsonl      工具/阶段时间线
mutations.json    设备改动及恢复命令
dexdump/raw       Frida/磁盘/dd 原始 DEX
dexdump/fixed     修复、去重、重命名后的 classes*.dex + manifest.json
dexdump/jadx      JADX 输出
logs/              Frida 与命令日志
```

默认根目录 `%LOCALAPPDATA%\apk-unpack\runs`，可用 `--runs-dir` 或 `APU_RUNS_DIR` 覆盖。源 APK 永远只读。

## MCP 工具

`inspect_apk`、`extract_apk_assets`、`inspect_android_device`、`prepare_android_environment`、`launch_android_target`、`inspect_process_state`、`recommend_unpack_strategy`、`dump_android_dex`、`repair_android_dex`、`verify_android_dex`、`decompile_android_apk`、`get_evidence`、`export_evidence_bundle`、`inspect_run`、`cleanup_run`、`recall_unpack_lessons`、`remember_unpack_lesson`。

MCP 启动：

```json
{
  "mcpServers": {
    "apk-unpack": {
      "command": "python",
      "args": ["-m", "apk_unpack", "mcp"],
      "env": { "PYTHONPATH": "src" }
    }
  }
}
```

## 环境变量

| 变量 | 用途 |
|---|---|
| `APU_RUNS_DIR` / `APU_HOME` | 运行目录根 |
| `APU_MEMORY_DIR` | 经验记忆目录（默认 `%LOCALAPPDATA%\apk-unpack\memory`） |
| `APU_ADB` / `APU_FRIDA` / `APU_FRIDA_PS` | 工具命令覆盖 |
| `APU_FRIDA_SERVER` | 本地 frida-server 路径（自动 push） |
| `APU_FRIDA_HOST` / `APU_FRIDA_PORT` | Frida 连接（默认 127.0.0.1:27042） |
| `APU_AAPT` / `APU_JAVA` / `APU_JADX_JAR` | 静态/反编译工具 |
| `APU_MAX_REGION_BYTES` | 单内存区 dump 上限（默认 256 MiB） |
| `APU_MCP_MAX_RESPONSE_BYTES` | MCP 响应预算（默认 8 MiB） |
| `APU_WEB_DEVICE_START_CMD` | 任务选择“自动/默认”且无在线设备时执行的启动命令（如 `docker start redroid`） |
| `APU_WEB_DEVICE_AUTO_CREATE` | 设为 `1` 时，无设备可用会自动创建新 redroid 容器（默认关闭） |
| `APU_WEB_DEVICE_IMAGE` | 自动创建使用的镜像（默认 `erstt/redroid:11.0.0_ndk_ChromeOS`） |
| `APU_WEB_DEVICE_PORT_START` / `APU_WEB_DEVICE_PORT_END` | 自动创建容器的端口范围（默认 5557–5599） |
| `APU_WEB_DEVICE_MAX_CONTAINERS` | 自动创建的 redroid 容器上限（默认 2） |
| `APU_WEB_DEVICE_CREATE_TIMEOUT_S` | 等待新环境 adb 就绪的超时秒数（默认 120） |
| `APU_WEB_DEVICE_ARM_ENABLED` | 启用 ARM64 redroid 运行底座（默认 `1`） |
| `APU_WEB_DEVICE_ARM_FALLBACK` | x86 脱壳失败后自动改用 ARM64 重试一次（默认 `0`；ARM 底座验证通过后设为 `1`） |
| `APU_WEB_DEVICE_ARM_IMAGE` | ARM64 底座镜像（默认 `apu-redroid-arm64:12-64only`，由 `deploy/build-arm-redroid.sh` 构建） |
| `APU_WEB_DEVICE_ARM_PLATFORM` | 拉取/运行多架构镜像时的 platform；单架构本地镜像留空 |
| `APU_WEB_DEVICE_ARM_MAX_CONTAINERS` | 自动创建的 ARM64 容器上限（默认 1） |
| `APU_WEB_DEVICE_ARM_CREATE_TIMEOUT_S` | ARM64 容器启动与 adb 就绪超时（默认 1800 秒，QEMU 很慢） |
| `APU_FRIDA_SERVER_ARM64` | ARM64 设备使用的 frida-server 路径（如 `/opt/apu-web/bin/frida-server-arm64`） |

## Web 后台（三底座）

`backend/` 提供带登录、上传、队列、实时 SSE、DEX/源码下载、经验库、Agent/Skill/MCP 管理、模型接入的后台：

- Agent：内置确定性 Agent + 每个模型 Provider 自动生成的 LLM Agent + 自定义 Agent；任务页默认选中可用的模型 Agent（优先 DeepSeek OpenAI 协议），确定性 Agent 排在第二位
- 模型协议：OpenAI（`/chat/completions`）、Anthropic（`/v1/messages`）与 `auto` 自动兼容；任意 Base URL / Key 可用于任一 Agent 底座
- DeepSeek 预设：`https://api.deepseek.com` 与 `https://api.deepseek.com/anthropic`
- Skill：内置 `unpack-android-apk` + 用户自定义通用 Skill
- MCP：HTTP JSON-RPC / stdio，可测试 `tools/list`，工具会注入 LLM tool loop
- **聊天**：任务与经验库之间的独立聊天页，可新建/重命名/清空/删除会话，选择任意可用 Agent（DeepSeek/Claude/自定义），自动加载该 Agent 的 Skills 并执行其 MCP 工具；也可用自然语言让聊天创建个人 Skill/MCP/Agent（显式请求时触发，普通用户限 HTTP MCP）
- **聊天附件**：每条消息最多 5 个文件、单文件 20 MB；文本自动读入上下文，二进制/APK 保留服务器路径供 MCP 工具使用，支持附件下载与随聊天删除
- **个人资源**：所有登录用户都能在管理页新增/编辑自己的 Agent / Skill / MCP；共享资源只读使用，私有 Agent 只能引用共享或自己的 Skill/MCP；普通用户仅可添加 HTTP MCP（stdio 仅管理员）
- **设备登记**：设备列表每次刷新都会自动登记已连接 adb 设备；支持手动添加（留空 Serial 自动扫描、裸 IP 自动补 5555、名称自动生成），删除只隐藏不断连，离线设备保留
- **聊天操作后台**：自然语言查询任务/上传/设备/经验库，并可显式要求创建、取消、重试任务或登记设备
- **ZIP 包导入**：Agents / Skills / MCP 面板可直接上传 ZIP，自动识别 `SKILL.md`、`mcp/*.json`、`.mcp.json`、Agent manifest 并安装；同名/同 id 非覆盖跳过；普通用户导入为个人资源
- **中英文切换**：右上角 English / 中文一键切换，静态与动态界面同步切换
- **任务列表**：分页 + 固定高度滚动卡片布局，窄屏自动换行，无横向滑动；支持单任务删除
- **存储管理**：单个/批量清理已结束任务、无引用上传 APK、孤立运行目录，显示磁盘占用
- 任务详情分别显示 Agent 配置、工具调用、Skill 加载与 MCP 调用
- 用户管理：删除/禁用/降级必须保留至少一个可用管理员；重置密码会使会话失效
- Docker：`backend/docker-compose.yml` 启动 redroid + 后台；镜像构建文件为 `backend/Dockerfile`
- 文档：`backend/README.md`

```powershell
cd backend
$env:PYTHONPATH = "..\src"
$env:APU_WEB_ADMIN_USER = "admin"
# 不设置 APU_WEB_ADMIN_PASSWORD 时首次启动生成随机密码
python -m backend serve
# http://127.0.0.1:8080
```

## 测试

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m unittest discover -s tests -v
python -m unittest discover -s backend/tests -t . -v
```

真机测试默认跳过；设置 `APU_DEVICE_TESTS=1` 并连接设备后启用。当前实现中，静态检测、DEX 修复/验证、策略、MCP 协议与 CLI 已可离线验证；ijiami 的 Frida/dd/冻结链路已在 ChatCube 与 2.apk 上真机验证，Bangcle/360/Tencent MTP/非 root 仍待补样本。

## 设计文档

- [docs/architecture.md](docs/architecture.md)
- [docs/tool-design.md](docs/tool-design.md)
- [docs/cli.md](docs/cli.md)
- [docs/mcp-contracts.md](docs/mcp-contracts.md)
- [docs/installation.md](docs/installation.md)
- [docs/memory.md](docs/memory.md)
- [.agents/skills/unpack-android-apk/SKILL.md](.agents/skills/unpack-android-apk/SKILL.md)
