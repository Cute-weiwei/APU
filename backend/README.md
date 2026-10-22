# APK Unpack Web Backend

带登录、上传、队列、实时 SSE、DEX/源码下载、经验库、MCP 和三执行底座的后台。

- 底座：`agent`（确定性工作流）/ `deepseek`（OpenAI 兼容 tool loop）/ `claude`（Anthropic Messages tool-use）
- 账号：本机部署示例使用 `admin / change-me`（生产请修改）
- 数据目录：默认 `backend/data`，Ubuntu 部署示例为 `/opt/apu-web/data`
- 端口：`8080`

源码下载 `source.zip` 保留 Java 文件的原有目录，同时包含 `resources/` 和已提取的
`assets/`（含 uni-app / Hybrid 的 JS、HTML、CSS）。`SOURCE_REPORT.json` 记录 DEX
校验和反编译质量；存在损坏 DEX 或 JADX 未还原的方法时，任务显示为“部分成功”，
已恢复的 DEX 和源码仍可下载。DEX 结构校验通过不代表已恢复应用的全部业务代码。

## 直接运行（Linux / Windows 均可）

```bash
cd apk-unpack-agents
export PYTHONPATH=src
export APU_WEB_DATA_DIR=/opt/apu-web/data
export APU_WEB_HOST=0.0.0.0
export APU_WEB_PORT=8080
export APU_WEB_ADMIN_USER=admin
export APU_WEB_ADMIN_PASSWORD=change-me
export APU_WEB_SERIAL=127.0.0.1:5555
export APU_REDROID_ADDR=127.0.0.1:5555
export APU_FRIDA=/opt/apu-web/venv/bin/frida
export APU_FRIDA_PS=/opt/apu-web/venv/bin/frida-ps
export APU_FRIDA_SERVER=/opt/apu-web/bin/frida-server
export APU_JADX_JAR=/opt/apu-web/jadx/jadx-all.jar
export APU_JAVA=/usr/bin/java
python -m backend serve
```

打开 `http://127.0.0.1:8080`，用 `admin/change-me` 登录。

首次启动时如果没有用户，会按 `APU_WEB_ADMIN_USER/PASSWORD` 创建 admin；没有密码时生成随机密码写入 `data/admin_password.txt`。

## Ubuntu + redroid（当前验证方式）

```bash
apt-get update
apt-get install -y adb openjdk-17-jre-headless python3-venv curl unzip

# 准备 frida / jadx / agent（参考 /opt/apu-web 布局）
python3 -m venv /opt/apu-web/venv
/opt/apu-web/venv/bin/pip install -e /opt/apu-web/repo/apk-unpack-agents
/opt/apu-web/venv/bin/pip install frida==17.8.2 frida-tools

# redroid（需要宿主机 binderfs）
docker run -itd --privileged --name redroid \
  -p 127.0.0.1:5555:5555 \
  -v /dev/binderfs:/dev/binderfs -v redroid-data:/data \
  erstt/redroid:11.0.0_ndk_ChromeOS \
  androidboot.hardware=redroid androidboot.redroid_gpu_mode=guest \
  androidboot.use_memfd=1 androidboot.redroid_width=720 androidboot.redroid_height=1280

adb connect 127.0.0.1:5555
adb -s 127.0.0.1:5555 root
```

验证 ARM 翻译：

```bash
adb -s 127.0.0.1:5555 shell getprop ro.product.cpu.abilist
# x86_64,x86,arm64-v8a,armeabi-v7a,armeabi
adb -s 127.0.0.1:5555 shell getprop ro.dalvik.vm.native.bridge
# libnb.so -> libndk_translation.so
```

启动后台（后台进程使用同一组 `APU_*` 环境变量），然后：

```bash
curl http://127.0.0.1:8080/api/v1/health
```

## 模型接入（OpenAI / Anthropic 协议）

后台管理页的 **模型接入** 支持可视化增删改查：

- 协议：`openai`（`/chat/completions`）、`anthropic`（`/v1/messages`）或 `auto`（任一 URL/Key 自动尝试两种协议）
- Base URL、模型、上下文窗口、最大输出 tokens、最大步数、超时、温度均可配置；任意 URL/Key 可绑定到任意 Agent 底座，不限定 DeepSeek/Claude 品牌
- 内置预设会自动填充：

```text
OpenAI 协议     https://api.deepseek.com
Anthropic 协议  https://api.deepseek.com/anthropic
模型            deepseek-chat
上下文/输出     65536 / 8192
```

- API Key 只写入 `data/secrets/provider-<id>.key`（0600），数据库只保存模型元数据；接口只返回 `sk-…abcd` 掩码
- **测试连接** 会分别按所选协议发起一次最小请求；**拉取模型** 对 OpenAI 协议调用 `/models`（Anthropic 协议返回常用预设）
- 每个模型 Provider 自动生成一个可编辑的 Agent；Agent 可挂载 Skills 和 MCP

环境变量仍可作为首次播种和旧任务兼容：`DEEPSEEK_API_KEY`、`DEEPSEEK_BASE_URL`、`DEEPSEEK_MODEL`、`ANTHROPIC_API_KEY`、`ANTHROPIC_BASE_URL`、`CLAUDE_MODEL`。已存在的 Provider 不会被环境变量覆盖。

## Agent / Skill / MCP

- **Agents**：内置确定性 Agent + 每个 Provider 自动生成的 LLM Agent + 用户自定义 Agent
  - 任务页“Agent / 模型”默认选中可用的模型 Agent，优先 DeepSeek OpenAI 协议；确定性 Agent 固定在模型 Agent 之后（第二位）；没有可用模型时才回退到确定性 Agent
  - API / 聊天创建任务不传 `engine` 时同样使用上述默认顺序
  - 自定义 Agent 选择 Provider、Skills、MCP、附加系统提示词
  - 任务创建时直接选择 Agent；旧任务的 `agent/deepseek/claude` 会自动映射到新 Agent
- **Skills**：内置 `unpack-android-apk` 只读；用户可新增通用 Markdown Skill，支持启用/停用
- **MCP**：支持 HTTP JSON-RPC 和 stdio；Headers/Env 存入 0600 密钥文件；测试会执行 `initialize` + `tools/list`
  - 绑定到 Agent 后，MCP 工具以 `mcp__<server>__<tool>` 注入 OpenAI/Anthropic tool loop
- **个人资源（所有登录用户）**：Agent / Skill / MCP 都带 `owner_id`
  - 管理员创建的资源是**共享资源**（`owner_id=NULL`），所有用户可见、只读使用
  - 普通用户可新增/编辑/删除**自己的私有资源**，在聊天、任务和 Agents/Skills/MCP 面板中只见“共享 + 我的”
  - 私有 Agent 只能绑定共享资源或同一用户的私有资源；共享 Agent 只能绑定共享资源
  - 普通用户只能创建 **HTTP** MCP；stdio 命令会在服务器执行，仅管理员可配置
  - 删除用户会级联删除其私有资源；ZIP 导入同样按导入者的归属安装
- **实时显示**：任务详情页分别展示 Agent 配置、工具调用、Skill 加载、MCP 连接/调用；SSE 事件与调用记录同步刷新

## 设备登记（自动 + 手动）

- `GET /api/v1/devices` 每次都会扫描 adb，并把已连接设备**自动登记**到 `devices` 表；离线设备保留为 `offline`，重启/刷新后仍在列表中。
- 手动添加（管理员）：`POST /api/v1/devices`。`serial` 可以为空——留空即自动扫描并登记全部已连接设备；只填 `127.0.0.1` 会自动补成 `127.0.0.1:5555`；名称为空时自动生成（如 `redroid-5556`）。
- `PATCH /api/v1/devices/{serial}` 修改名称/备注/类型/启用状态；`DELETE` 只把设备从列表**隐藏**，不会断开 adb，后续扫描也不会重新显示，重新添加即可恢复。
- 任务创建和聊天工具都会引用同一张设备表；聊天可使用 `apu_list_devices` / `apu_register_device` 自然语言登记设备。
- **自动设备（任务页选择“自动/默认”）**：没有显式指定 serial 时，按“配置的 `APU_WEB_SERIAL`（若在线）→ 任一在线设备 → 已登记的网络设备（自动 `adb connect`）”顺序选择；仍无在线设备且设置了 `APU_WEB_DEVICE_START_CMD`（例如 `docker start redroid`）时，会执行一次启动命令并在约 30 秒内轮询重连。
- **自动创建环境**：开启 `APU_WEB_DEVICE_AUTO_CREATE=1` 后，如果启动命令仍无法提供设备，后台会自动 `docker run` 一个新的 redroid 容器（名称 `apu-redroid-<端口>`，独立 `-data` 卷，端口从 `APU_WEB_DEVICE_PORT_START` 起自动选空闲值），等待 adb 连接和 `sys.boot_completed=1` 后登记为设备并用于当前任务；创建失败会删除半成品容器并返回 `device_unavailable`。最多同时保留 `APU_WEB_DEVICE_MAX_CONTAINERS` 个自动环境（默认 2）。自动创建的容器不会随任务结束自动删除，可在宿主机用 `docker rm -f <name>` 清理。

## 聊天 / 中英文 / 存储

### JADX 时限与结果

- 默认 Java 堆上限为 4096 MiB，不随 APK 大小自动增加。
  可用 `APU_JADX_HEAP_MB` 显式指定（0 使用默认上限）。大包部署需要足够的 RAM 与 swap。
  超过 64 MiB 的输入采用 SerialGC，将更多堆空间留给长期保留的类信息；主解析和备用解析使用相同配置。
  这不会取消堆上限，生产部署还应通过容器或 systemd 限制进程组的内存与 swap。
- 超过 64 MiB 的输入关闭匿名类、方法和 Kotlin lambda 内联，保留独立类与方法调用，
  降低重建过程的内存占用；所有 DEX 仍参与同一次解析，报告记录 `profile=no_inline`。
  进程异常退出单独报告 `jadx_process_error`，不会混同普通重建警告；JVM 堆耗尽时立即退出并保留诊断。
  大型证据返回紧凑的状态与数量摘要，避免 AI 因文件列表被截断而重复整包 JADX；DEX 校验默认不调用 JADX。
- 单个 DEX 的复核结果不会覆盖整包校验及源码质量记录。源码 ZIP 使用质量记录对应的输出目录，
  避免将另一次解析的文件和当前统计混用；重复解析使用独立目录。

- 默认 `APU_JADX_THREADS=1`，主解析和备用指令解析均限制并发，降低大 APK 的 Java 堆峰值。
  需要提速且内存足够时可配置 1–64；任务报告记录实际默认线程数和完整执行命令。

- 已 dump 的 DEX 若覆盖且逐字节匹配原 APK 的全部 DEX，反编译会使用原 APK 容器保留资源表上下文，
  同时带上所有额外运行时 DEX；避免把大型生成的 R 类作为裸 DEX 重建造成内存压力。
  加固包、字节已改变、只取得部分 DEX 或原 APK 改变时不会这样替换。
- `jadx_memory` 明确报告 Java 堆耗尽；这属于主进程失败，不能当作普通混淆警告。
  主进程失败后的备用解析会保留全部类的指令视图，避免只保留已有警告文件而遗漏尚未写出的类。

- “强制 DEX dump”会传给策略工具，AI 与原生引擎均遵守。若只产生静态 DEX，
  任务报告 `runtime_dump_incomplete`，不能冒充已完成运行时 dump。
- 默认 JADX 遇到源码重建错误时，会在剩余预算内尝试一次 fallback；只把失败类及其内类的
  原始指令视图放入源码 ZIP 的 `recovery/fallback/`，附报告和说明。正常 Java 不覆盖，
  这些备用文件不是可编译 Java，源码状态仍保留 `partial`。

- 默认 JADX 时限为 3600 秒，可通过服务器环境变量 `APU_JADX_TIMEOUT_S` 修改。
  单任务高级选项 `jadx_timeout_s` 优先；未指定或 0 使用服务器默认。
  原生、AI 引擎使用相同时限，AI 工具参数不能覆盖任务设置。
- 未指定总时限时，预留 3600 秒工作流预算，加上启用的 JADX 时限（默认共 7200 秒）。
  显式指定的 `timeout_s` 仍为硬上限，设得比 JADX 时限短会提前终止任务。
- `jadx_timeout` 表示反编译运行超时；`jadx_incomplete` 表示反编译报错或有警告。
  两者均保留 DEX 和已生成的源码。DEX 校验通过但源码不完整时仍标记 `partial`，
  任务详情单独说明源码状态，不能据此断言脱壳失败。
  证据和源码 ZIP 的 `SOURCE_REPORT.json` 包含实际时限、耗时和超时标记。

- **聊天页**位于「任务」和「经验库」之间：新建、重命名、清空、删除会话；选择任意可用 Agent（DeepSeek / Claude / 自定义）；自动注入该 Agent 的 Skills，并通过其 MCP 工具执行调用；展示工具事件与用量。
- **聊天内自然语言新增资源**：内置 `apu_list_resources` / `apu_create_skill` / `apu_create_mcp` / `apu_create_agent` 四个工具。用户明确说“帮我新增一个 Skill/MCP/Agent”时，模型会创建资源并自动归属当前用户（管理员创建的是共享资源）；普通用户不能通过聊天创建 stdio MCP。创建结果以“资源工具/资源返回”事件显示。
- **聊天直接操作后台**：内置 `apu_backend_overview`、`apu_list_jobs`、`apu_get_job`、`apu_list_uploads`、`apu_create_task`、`apu_cancel_job`、`apu_retry_job`、`apu_list_devices`、`apu_register_device`、`apu_list_lessons`。可以自然语言查询任务/上传/设备/经验库，也可以显式要求创建、取消、重试任务或登记设备；只读工具可随时使用，写操作要求用户明确指令。
- **聊天附件**：每条消息最多 5 个文件、单文件 20 MB。文本类文件（md/json/log/py 等）自动读入上下文，二进制/APK 等保留服务器路径供 MCP 工具处理；支持下载附件，删除/清空聊天时一并清理 `data/chat-files`。
- **中英文切换**在右上角：静态界面、任务/存储/聊天/经验库等动态内容同步切换；用户输入、文件名、日志和聊天正文保持原文。
- **任务列表**为固定高度可滚动卡片 + 分页，窄屏自动换行，不再横向滑动；单个任务可删除。
- **管理 → 存储**：查看上传/任务产物/运行目录/磁盘占用；删除单个上传 APK（有关联任务时同步删除）、批量清理已结束任务、无引用上传和孤立运行目录。

### API

```text
GET/POST  /api/v1/chats
GET/PATCH/DELETE /api/v1/chats/{id}
POST      /api/v1/chats/{id}/messages
POST      /api/v1/chats/{id}/clear
GET       /api/v1/chat/agents
POST      /api/v1/chats/{id}/files
GET       /api/v1/chats/{id}/files/{file_id}
GET       /api/v1/storage
POST      /api/v1/storage/cleanup
GET       /api/v1/lessons/export
POST      /api/v1/lessons/import
POST      /api/v1/packages/import
```

资源共享规则：普通用户调用列表接口只返回“共享 + 自己的”资源；只有资源所有者或管理员能修改/删除；`POST /api/v1/agents`、`/skills`、`/mcp-servers` 对普通用户自动写入 `owner_id`。

## ZIP 包导入（Skill / MCP / Agent）

管理页的 Agents / Skills / MCP 面板都有 **导入 ZIP**，上传后自动分析并安装；统一接口 `POST /api/v1/packages/import`（所有登录用户，multipart `file`；普通用户安装为个人资源）。

支持格式：

```text
# Skill
SKILL.md
skills/<name>/SKILL.md          # 自动用目录名作为 id（可被 Agent 引用）
（可选 YAML front matter: name/description/id；references/*.md 会合并进内容）

# MCP
mcp/<name>.json                 # {id,name,transport,url|command,args,headers,env}
# 或 Claude/Cursor 风格：
.mcp.json                       # {"mcpServers": {"name": {...}}}
# 或 manifest.json:
{"type":"mcp","name":"...","transport":"stdio","command":"npx","args":["-y","..."]}

# Agent
agents/<name>.json
# 或 manifest.json:
{"type":"agent","name":"...","provider_id":"deepseek-openai",
 "skill_ids":["my-skill"],"mcp_ids":["my-mcp"],"system_prompt":"..."}
# provider_id / provider_name 必须是已存在的 Provider；
# skill/mcp 可引用包内（按目录名/id）或已有资源。
```

- 一个 ZIP 可以同时包含多种类型，安装顺序为 Skill → MCP → Agent。
- 同名或同 id 已存在时跳过，不覆盖；重复导入安全。
- ZIP 有路径穿越、符号链接、条目数/解压大小/单文件大小限制；MCP stdio 命令不会在导入时执行。
- 导入结果返回 `installed` / `skipped` / `errors`，并写审计日志。

`/storage/cleanup` 的 `target` 可为 `completed_jobs`、`orphan_uploads`、`orphan_runs`、`orphan_job_dirs`、`all`，`older_than_days=0` 表示全部符合条件记录。运行中的任务不会被删除。

## 经验库自动生成

每个后台任务结束（成功、部分成功、失败；静态、动态、Agent、OpenAI、Anthropic）都会自动生成并保存一条经验，无需手工添加：

- 记录：壳、设备 ABI、APK ABI、框架、所用 Agent、成功/失败方法、症状、根因、解法、证据链接、示例运行
- 静态 APK：自动识别 `static_jadx` / `static_dex_extract` 路线并记录“无需运行时 dump”
- 动态壳：优先使用 `last_dump` 的实际成功方法；失败任务记录失败方法链，`success_count` 不增加
- **只记录有价值的结果**：
  - 成功/部分成功必须在运行目录里实际产生 `dexdump/fixed/*.dex` 或 JADX `sources`，没有产物不记录
  - 启动阶段就 `process_died`、SIGKILL、native-bridge / 反模拟器导致的 job 级失败，即使还没进入 dump，也会记录为 “startup pitfall”
  - 已经执行过 dump 方法但全部失败的 job 会记录失败方法链与错误码/消息（如 `memory_dd + memory_dd_retry + freeze_dd`），作为踩坑经验；纯配置/网络错误仍跳过
  - 静态直读作为“无需 dump”的优化经验记录
- **强去重**：第一层按“壳 + 设备 ABI + APK ABI + 框架 + 成功方法 + 失败方法名”生成稳定 route key，错误码/错误文本不同也视为同一经验，只合并 `occurrences`，不会新增条目；第二层按精确 fingerprint 去重
- 原生 Agent 已记录的 fallback / emulator-bypass 经验会被识别并复用，不会重复计数
- 任务详情会实时出现 `lesson_recorded` / `lesson_skipped` / `lesson_record_failed`，`deduped=true` 表示命中已有经验；经验库页显示统计与“自动/手工”筛选

存储位置：`data/memory/lessons.json`（由 Agent 与后台共用）。

### 下载与分享导入

- `GET /api/v1/lessons/export` 下载 JSON 文档（包含 schema、stats、全部 lessons）。
- `POST /api/v1/lessons/import` 接受导出文档、`{lessons:[...]}` 或 lessons 数组。
- 导入是**非覆盖**的：按重新计算的 fingerprint / lesson_id 去重，只添加新经验，不修改已有经验；重复导入同一文件会全部跳过。
- 任何已登录用户都可以下载和导入；导入会写审计日志。

## API 摘要

- `POST /api/v1/auth/login` `{username,password}` → `{token,user}`
- `POST /api/v1/uploads` multipart `file`
- `POST /api/v1/jobs` `{upload_id, engine, serial, options{install,jadx,cleanup,force_dump,...}}`
- `GET /api/v1/jobs`、`GET /api/v1/jobs/{id}`
- `GET /api/v1/jobs/{id}/stream`（SSE）
- `GET /api/v1/jobs/{id}/download/{dex|source|evidence|logs|full}`
- 模型：`GET/POST /api/v1/providers`、`PATCH/DELETE /api/v1/providers/{id}`、`POST /api/v1/providers/{id}/test`、`GET /api/v1/providers/{id}/models`、`GET /api/v1/providers/presets`
- Agent：`GET/POST /api/v1/agents`、`PATCH/DELETE /api/v1/agents/{id}`
- Skill：`GET/POST /api/v1/skills`、`PATCH/DELETE /api/v1/skills/{id}`
- MCP：`GET/POST /api/v1/mcp-servers`、`PATCH/DELETE /api/v1/mcp-servers/{id}`、`POST /api/v1/mcp-servers/{id}/test`
- `POST /mcp`（JSON-RPC，Bearer）
- `GET /api/v1/devices`、`/engines`、`/doctor`、`/lessons`

## Docker

推荐使用版本化的一键安装：

```bash
cd apk-unpack-agents/backend
docker compose up -d --build
```

它会生成带随机管理员密码的 `.env`、启动 redroid + 后台并等待健康检查。也可以继续使用 `backend/docker-compose.yml`：

```bash
cd apk-unpack-agents/backend
docker compose up -d --build
```

- redroid 需要宿主机 `/dev/binderfs` 已挂载；无 KVM 也可运行。
- Docker Hub 直连不可用时，先配置 registry mirror（例如 `docker.1ms.run`、`docker.xuanyuan.me`）。
- `Dockerfile` 会下载 JADX 1.5.6 和 frida-server 17.8.2 x86_64，并校验固定 SHA-256；内网镜像文件须同时提供匹配的 URL 和 SHA-256 参数。

## redroid / 纯 ARM 爱加密自毁（实验性 shield）

`backend/tools/redroid_shield.py` 可以把 `src/apk_unpack/scripts/apu_shield.c` 编译后通过
Android `wrap.<package>`（LD_PRELOAD）注入目标进程，实验性地处理以下自毁路径：

- 在启动早期 fork 一个不受过滤监督进程，安装 seccomp user-notification；
- 伪造 `/proc/self/maps`、`/proc/self/status`、`/proc/self/wchan`、`/proc/self/environ`、
  `/proc/cpuinfo`、`/proc/self/auxv`、`/sys/devices/system/cpu/*`、`/system/build.prop`；
- 伪造 `ro.dalvik.vm.native.bridge`、`ro.debuggable`、`ro.product.cpu.abilist*` 等属性；
- 伪造 `uname` / `AT_HWCAP` / `AT_PLATFORM`，隐藏 x86_64 与 native bridge 特征；
- 拦截自定向 `SIGKILL` / `exit_group`，并让 SIGILL/SIGSEGV 线程暂停而不是杀死进程。

```bash
python backend/tools/redroid_shield.py --serial 127.0.0.1:5555 --package com.example.app --apply
adb -s 127.0.0.1:5555 shell cat /data/local/tmp/apu_shield.log
python backend/tools/redroid_shield.py --serial 127.0.0.1:5555 --package com.example.app --clear
```

验证结果（当前 redroid 11 + libndk + 2.apk）：shield 能阻止最初的 SIGKILL 并隐藏 ABI/属性/auxv
特征，进程可存活更久；但该样本的新版爱加密 VM 仍会执行内部 `ud2`，随后进入 SIGABRT/SIGSEGV
自毁。`--skip-traps` 实验模式可以单步跳过 `ud2`，实测进程从约 1 秒延长到 8 秒以上并加载
`libexec.so`/`libexecmain.so`，但后续仍有 SIGABRT 和多次空指针类 SIGSEGV，未出现可 dump 的 DEX。
也就是说，shield 是“研究/缓解”工具，不是对所有新版爱加密壳的完整绕过。

Houdini 镜像尝试：`erstt/redroid:11.0.0_houdini_ChromeOS` 默认仍是 `libnb.so -> libndk_translation.so`；
把链接改成 `libhoudini.so` 后 Houdini 初始化失败（`Initialize library ... failed(0x00010002)`），
进程启动即崩溃，因此该镜像在当前环境不可用。要稳定脱壳纯 ARM 爱加密，仍建议兼容的 Houdini
翻译环境、ARM64 主机或物理 ARM64 设备。

## 已知环境限制

- redroid/libndk 上，部分 ARM-only 的 ijiami 壳会在加载 `libexec.so` 后快速自毁（反容器/反
  native-bridge），此时没有 DEX 窗口。可尝试上面的实验性 shield；更稳妥的是 Houdini 镜像、
  ARM64 主机或物理设备。
- 后台新增的模型协议 `auto` 会先按 URL/模型选择协议，再在端点/格式错误时自动切换另一种协议；
  这使同一个 URL/Key 能同时服务 Claude 风格与 DeepSeek 风格 Agent。
- 普通 APK / 系统 APK 的动态 dump、修复、JADX、下载链路已在 Ubuntu + redroid 上验证（Settings: 1 DEX / 7,749 类，源码 3,624 个 Java 文件）。
- 安装 APK 保留在设备上，不自动卸载。
