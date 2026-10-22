(() => {
  "use strict";

  const EN = {
    "账号密码登录 · Agent / OpenAI / Anthropic 三底座": "Sign in · Agent / OpenAI / Anthropic engines",
    "用户名": "Username",
    "密码": "Password",
    "登录": "Sign in",
    "任务": "Tasks",
    "聊天": "Chat",
    "经验库": "Lessons",
    "管理": "Manage",
    "账号": "Account",
    "退出": "Log out",
    "上传 APK": "Upload APK",
    "点击选择或拖入 APK": "Click to choose or drop an APK",
    "模型": "Model",
    "Agent / 模型": "Agent / model",
    "Agent（确定性）": "Agent (deterministic)",
    "JADX 源码": "JADX source",
    "设备": "Device",
    "自动/默认": "Auto / default",
    "安装 APK": "Install APK",
    "源码": "Source",
    "自动清理": "Auto cleanup",
    "保留设备文件": "Keep device files",
    "自动模拟器绕过": "Auto emulator bypass",
    "使用ARM模拟器（速度慢）": "Use ARM emulator (slow)",
    "直接使用 ARM64 redroid 运行，速度很慢": "Run directly on ARM64 redroid; this is much slower",
    "上传并开始脱壳": "Upload and start unpacking",
    "上传完成后自动创建任务；任务进度通过 SSE 实时推送。": "A task is created after upload; progress is streamed over SSE.",
    "任务列表": "Task list",
    "加载中…": "Loading…",
    "按状态筛选": "Filter by status",
    "全部状态": "All statuses",
    "排队中": "Queued",
    "运行中": "Running",
    "成功": "Succeeded",
    "部分成功": "Partial",
    "失败": "Failed",
    "已取消": "Cancelled",
    "刷新": "Refresh",
    "刷新全部": "Refresh all",
    "暂无任务": "No tasks",
    "上一页": "Previous",
    "下一页": "Next",
    "任务详情": "Task details",
    "取消": "Cancel",
    "重试": "Retry",
    "关闭": "Close",
    "调用记录": "Call records",
    "工具 / Skill / Agent / MCP": "Tools / Skill / Agent / MCP",
    "工具": "Tools",
    "经验": "Lessons",
    "实时事件": "Live events",
    "新聊天": "New chat",
    "暂无聊天": "No chats",
    "选择 Agent 后开始对话": "Choose an Agent to start chatting",
    "重命名": "Rename",
    "清空": "Clear",
    "删除": "Delete",
    "新建聊天并发送第一条消息": "Create a chat and send the first message",
    "输入消息…（Ctrl+Enter 发送）": "Type a message… (Ctrl+Enter to send)",
    "输入消息…（Enter 发送，Shift+Enter 换行）": "Type a message… (Enter to send, Shift+Enter for a new line)",
    "聊天列表": "Chat list",
    "发送": "Send",
    "发送中…": "Sending…",
    "停止": "Stop",
    "正在停止…": "Stopping…",
    "已停止": "Stopped",
    "任务完成自动生成 / 自动保存": "Generated automatically when a task finishes",
    "搜索症状/方案/壳/方法": "Search symptoms / solutions / shells / methods",
    "全部": "All",
    "自动": "Auto",
    "手工": "Manual",
    "搜索": "Search",
    "记录新经验": "Record a lesson",
    "标题": "Title",
    "壳（可选）": "Shell (optional)",
    "设备 ABI（可选）": "Device ABI (optional)",
    "场景/症状": "Scenario / symptoms",
    "实际解法": "Actual solution",
    "保存经验": "Save lesson",
    "我的账号": "My account",
    "角色": "Role",
    "修改密码": "Change password",
    "当前密码": "Current password",
    "新密码": "New password",
    "确认新密码": "Confirm new password",
    "更新密码": "Update password",
    "管理后台": "Manage console",
    "账号权限、模型协议、Agent / Skill / MCP 工具链与运行环境": "Accounts, model protocols, Agent / Skill / MCP tooling and runtime",
    "个人资源": "My resources",
    "新增并管理我的 Agent / Skill / MCP；共享资源由管理员维护，只读使用。": "Create and manage my Agents / Skills / MCP servers. Shared resources are admin-managed and read-only.",
    "我的": "Mine",
    "共享": "Shared",
    "资源工具": "Resource tool",
    "资源返回": "Resource result",
    "共享 Agent · 仅管理员可修改": "Shared agent · admin-managed",
    "共享 Skill · 只读": "Shared skill · read-only",
    "共享 MCP · 只读": "Shared MCP · read-only",
    "概览": "Overview",
    "存储": "Storage",
    "用户": "Users",
    "模型接入": "Models",
    "Agents": "Agents",
    "设备与底座": "Devices & engines",
    "审计": "Audit",
    "快速开始": "Quick start",
    "配置模型": "Configure models",
    "管理账号": "Manage accounts",
    "检查设备": "Check devices",
    "运行底座": "Engines",
    "存储与清理": "Storage & cleanup",
    "范围": "Range",
    "全部符合条件的记录": "All eligible records",
    "仅 7 天前": "Older than 7 days",
    "仅 30 天前": "Older than 30 days",
    "仅 90 天前": "Older than 90 days",
    "清理已结束任务": "Clean finished tasks",
    "清理无引用上传": "Clean unreferenced uploads",
    "清理孤立运行目录": "Clean orphan run dirs",
    "一键清理": "Clean all",
    "上传文件": "Uploaded files",
    "用户与权限": "Users & permissions",
    "新用户名": "New username",
    "初始密码（至少 4 位）": "Initial password (at least 4 chars)",
    "创建用户": "Create user",
    "新增模型": "Add model",
    "模型配置": "Model configuration",
    "名称": "Name",
    "协议": "Protocol",
    "自动兼容（OpenAI / Anthropic）": "Auto (OpenAI / Anthropic)",
    "OpenAI 协议": "OpenAI protocol",
    "Anthropic 协议": "Anthropic protocol",
    "留空保持不变": "Leave blank to keep",
    "上下文窗口": "Context window",
    "最大输出 tokens": "Max output tokens",
    "最大步数": "Max steps",
    "超时秒": "Timeout (s)",
    "温度": "Temperature",
    "启用": "Enable",
    "保存": "Save",
    "测试连接": "Test connection",
    "拉取模型": "Fetch models",
    "清空 Key": "Clear key",
    "新增 Agent": "Add Agent",
    "配置": "Configuration",
    "我的脱壳 Agent": "My unpack Agent",
    "模型 Provider": "Model Provider",
    "可多选）": "multi-select)",
    "附加系统提示词（可选）": "Additional system prompt (optional)",
    "保存 Agent": "Save Agent",
    "新增 Skill": "Add Skill",
    "描述": "Description",
    "内容": "Content",
    "保存 Skill": "Save Skill",
    "服务器": "Server",
    "新增 MCP": "Add MCP",
    "传输": "Transport",
    "命令": "Command",
    "清空 Headers/Env": "Clear Headers/Env",
    "保存 MCP": "Save MCP",
    "测试并列出工具": "Test and list tools",
    "运行": "Run",
    "点击运行检查环境": "Run to inspect the environment",
    "审计日志": "Audit log",
    "管理员": "Admin",
    "普通用户": "User",
    "不可用": "unavailable",
    "可用": "available",
    "无引擎信息": "No engine information",
    "已配置": "Configured",
    "未配置": "Not configured",
    "编辑": "Edit",
    "测试": "Test",
    "暂无模型，点击“新增模型”或上方预设。": "No models yet. Add one or use a preset above.",
    "名称必填": "Name is required",
    "必填": "required",
    "模型必填": "Model is required",
    "模型配置已保存": "Model configuration saved",
    "测试中…": "Testing…",
    "已保存": "Saved",
    "未配置 API Key": "API Key not configured",
    "模型已删除": "Model deleted",
    "内置": "Built-in",
    "确定性工作流": "deterministic workflow",
    "停用": "Disable",
    "暂无 Agent": "No Agents",
    "内置确定性 Agent 只能启用/停用": "The built-in deterministic Agent can only be enabled or disabled",
    "新增 Agent": "Add Agent",
    "请选择模型 Provider": "Choose a model Provider",
    "已启用": "Enabled",
    "已停用": "Disabled",
    "已删除": "Deleted",
    "查看/启用": "View / enable",
    "暂无 Skill": "No Skills",
    "名称和内容必填": "Name and content are required",
    "有 Headers/Env": "Headers/Env set",
    "无密钥": "No secret",
    "未测试": "Not tested",
    "测试工具": "Test tools",
    "暂无 MCP 服务器": "No MCP servers",
    "新增 MCP Server": "Add MCP Server",
    "不是合法 JSON": "Invalid JSON",
    "必须是 JSON 对象": "Must be a JSON object",
    "连接中…": "Connecting…",
    "连接成功": "Connected",
    "测试失败": "Test failed",
    "详情": "Details",
    "已请求取消": "Cancellation requested",
    "已创建重试任务": "Retry task created",
    "任务已删除": "Task deleted",
    "已结束": "Finished",
    "类型": "Type",
    "上下文": "Context",
    "协议 / 模型": "Protocol / model",
    "暂无调用记录": "No call records",
    "文件": "File",
    "状态": "Status",
    "阶段": "Stage",
    "默认": "Default",
    "错误": "Error",
    "下载 DEX": "Download DEX",
    "下载源码": "Download source",
    "下载证据": "Download evidence",
    "下载日志": "Download logs",
    "完整包": "Full bundle",
    "实时": "Live",
    "结束": "Finished",
    "重连中…": "Reconnecting…",
    "请先选择 APK": "Choose an APK first",
    "任务已创建": "Task created",
    "上传失败": "Upload failed",
    "总计": "Total",
    "壳分布": "Shell distribution",
    "暂停": "Pause",
    "框架": "Framework",
    "证据": "Evidence",
    "症状": "Symptoms",
    "根因": "Root cause",
    "解法": "Solution",
    "失败方法": "Failed methods",
    "场景": "Scenario",
    "暂无经验。完成任务后会自动生成并保存。": "No lessons yet. They are generated automatically when tasks finish.",
    "标题/场景/解法必填": "Title, scenario and solution are required",
    "经验已保存": "Lesson saved",
    "全选": "Select all",
    "删除所选": "Delete selected",
    "选择经验": "Select lesson",
    "编辑经验": "Edit lesson",
    "保存修改": "Save changes",
    "根因（可选）": "Root cause (optional)",
    "框架（可选）": "Framework (optional)",
    "标签（逗号分隔）": "Tags (comma separated)",
    "仅管理员可以修改或删除经验": "Only administrators can edit or delete lessons",
    "经验已更新": "Lesson updated",
    "经验已删除": "Lesson deleted",
    "经验不存在，请刷新后重试": "Lesson not found; refresh and try again",
    "标题不能为空": "Title is required",
    "请选择要删除的经验": "Select lessons to delete",
    "运行底座": "Engines",
    "可用 / 总数": "available / total",
    "磁盘": "Disk",
    "上传": "Uploads",
    "任务产物": "Task artifacts",
    "运行目录": "Run directories",
    "磁盘空间": "Disk space",
    "孤立数据": "Orphans",
    "暂无上传文件": "No uploaded files",
    "天前的": "days ago",
    "全部符合条件的": "all eligible",
    "已结束任务": "finished tasks",
    "无引用上传": "unreferenced uploads",
    "孤立运行目录": "orphan run directories",
    "创建时间": "Created",
    "操作": "Actions",
    "当前)": "(current)",
    "已禁用": "Disabled",
    "正常": "Active",
    "设为普通用户": "Make user",
    "设为管理员": "Make admin",
    "禁用": "Disable",
    "重置密码": "Reset password",
    "暂无用户": "No users",
    "用户角色已更新": "User role updated",
    "用户已禁用": "User disabled",
    "用户已启用": "User enabled",
    "密码至少 4 位": "Password must be at least 4 characters",
    "密码已重置，目标账号会话已失效": "Password reset; target sessions invalidated",
    "用户已删除": "User deleted",
    "用户已创建": "User created",
    "两次输入的新密码不一致": "The new passwords do not match",
    "密码已更新": "Password updated",
    "暂无审计": "No audit records",
    "检查中…": "Checking…",
    "没有可用的 Agent。请在管理 → Agents 新增个人 Agent，或由管理员配置模型 Provider。": "No Agent available. Create a personal Agent under Manage → Agents, or ask an administrator to configure a model Provider.",
    "暂无可用 Agent": "No Agents available",
    "删除聊天": "Delete chat",
    "调用": "Call",
    "返回": "Result",
    "工具错误": "Tool error",
    "还没有消息，输入内容开始对话": "No messages yet. Type something to start.",
    "你": "You",
    "条消息": "messages",
    "请先选择 Agent": "Choose an Agent first",
    "该 Agent 不可用": "This Agent is unavailable",
    "已创建新聊天": "New chat created",
    "思考中…": "Thinking…",
    "完成": "Done",
    "下载经验库": "Download lessons",
    "导入经验库": "Import lessons",
    "经验库可以下载后分享；导入采用非覆盖模式，只添加新经验，不修改已有经验。": "Lessons can be downloaded and shared. Import is non-overwriting: only new lessons are added; existing lessons are never modified.",
    "经验库已下载": "Lessons downloaded",
    "导入文件不能超过 8 MB": "The import file must be under 8 MB",
    "文件格式错误：需要包含 lessons 数组": "Invalid file: a lessons array is required",
    "导入完成": "Import complete",
    "导入 ZIP": "Import ZIP",
    "请选择 .zip 压缩包": "Choose a .zip package",
    "正在分析并安装 ZIP 包…": "Analyzing and installing the ZIP package…",
    "安装完成": "Installation complete",
    "附件": "Attach",
    "移除": "Remove",
    "请分析附件。": "Please analyze the attached files.",
    "每条消息最多上传 5 个附件": "At most 5 attachments per message",
    "上传附件": "Uploading attachment",
    "聊天已删除": "Chat deleted",
    "确认清空当前聊天记录？": "Clear the current chat history?",
    "聊天已清空": "Chat cleared",
    "聊天标题": "Chat title",
    "已切换聊天 Agent": "Chat Agent switched",
    "MCP 调用": "MCP call",
    "MCP 返回": "MCP result",
    "普通用户": "User",
    "自动兼容": "Auto compatible",
    "AI 助手": "AI assistant",
    "短": "Short",
    "快速开始": "Quick start",
    "清理任务产物、运行目录与不再被任务引用的上传 APK。删除不可恢复。": "Clean task artifacts, run directories and uploads no longer referenced by any task. Deletion cannot be undone.",
    "“已结束任务”包含成功、部分成功、失败、已取消；运行中的任务不会被删除。": "\"Finished tasks\" means succeeded, partial, failed or cancelled; running tasks are never deleted.",
    "必须始终保留至少一个可用管理员；删除、降级或禁用最后一个管理员会被拒绝。重置密码或禁用账号会使该账号的会话立即失效。": "At least one active administrator must remain. Demoting, disabling or deleting the last administrator is rejected. Resetting a password or disabling an account invalidates its sessions immediately.",
    "管理员可以在「管理 → 用户」创建账号、调整角色、重置密码或删除账号；系统始终至少保留一个可用管理员。": "Administrators can create accounts, change roles, reset passwords or delete accounts under Manage → Users. At least one active administrator is always kept.",
    "模型接入支持任意 Base URL + API Key，协议可选 OpenAI、Anthropic 或自动兼容；同一 URL/Key 可被任一 Agent 底座使用。": "Models accept any Base URL + API Key with OpenAI, Anthropic or auto protocol; the same URL/key can be used by any Agent.",
    "上传完成后自动创建任务；任务进度通过 SSE 实时推送。": "A task is created after upload; progress is streamed over SSE.",
    "每个任务结束（成功/失败/静态/动态）都会自动生成一条经验；相同壳 + 设备 ABI + APK ABI + 方法剖面会合并计数，不会重复刷屏。": "Every finished task (success / failure / static / dynamic) records a lesson; identical shell + device ABI + APK ABI + method profiles are merged instead of duplicated.",
    "内置 Skill 只读，自定义 Skill 可增删改；Agent 可选择挂载。": "Built-in Skills are read-only; custom Skills can be edited. Agents can attach them.",
    "支持 HTTP JSON-RPC 与 stdio（命令在服务器执行，仅管理员可配置）。Headers/Env 存在 0600 密钥文件。": "Supports HTTP JSON-RPC and stdio (commands run on the server; admins only). Headers/Env are stored in 0600 secret files.",
    "支持 OpenAI（/chat/completions）、Anthropic（/v1/messages）以及自动兼容。Base URL / 模型 / 上下文 / 输出 tokens 均可配置，任意 URL 与 Key 可用于任一 Agent 底座。API Key 只写入服务器 data/secrets（0600），接口只返回掩码，不进入数据库、日志或事件。": "Supports OpenAI (/chat/completions), Anthropic (/v1/messages) and auto-compatible protocols. Base URL, model, context window and output tokens are configurable; any URL/key can be used by any Agent. API keys are written only to server data/secrets (0600); the API returns masks only and never logs keys.",
    "每个 Agent 绑定一个 Provider，可选择 Skill 与 MCP。Provider 的协议决定该 Agent 使用 OpenAI、Anthropic 或自动兼容；确定性 Agent 固定使用内置脱壳工作流。也可上传 ZIP 包自动分析安装 Agent（包内可同时带 Skill / MCP）。": "Each Agent binds a Provider and can attach Skills and MCP servers. The Provider protocol decides whether the Agent uses OpenAI, Anthropic or auto-compatible mode; the deterministic Agent always uses the built-in unpacking workflow. You can also upload a ZIP package to install Agents automatically (the package may include Skills / MCP too).",
    "内置 Skill 只读，自定义 Skill 可增删改；Agent 可选择挂载。ZIP 包内包含 SKILL.md（或 skills/*/SKILL.md）即可自动安装。": "Built-in Skills are read-only; custom Skills can be added, edited and deleted. Agents can attach them. A ZIP package containing SKILL.md (or skills/*/SKILL.md) is installed automatically.",
    "支持 HTTP JSON-RPC 与 stdio（命令在服务器执行，仅管理员可配置）。Headers/Env 存在 0600 密钥文件。ZIP 包内包含 mcp/*.json、.mcp.json 或 manifest.json 即可自动安装。": "Supports HTTP JSON-RPC and stdio (commands run on the server; admins only). Headers/Env are stored in 0600 secret files. A ZIP package containing mcp/*.json, .mcp.json or manifest.json is installed automatically.",
    "MCP 服务器": "MCP servers",
    "确定性工作流 · deterministic workflow": "Deterministic workflow",
    "APK 脱壳（内置）": "APK unpacking (built-in)",
    "APK 脱壳(内置)": "APK unpacking (built-in)",
    "输出": "Output",
    "(当前)": "(current)",
    "（当前）": "(current)",
    "在线": "Online",
    "离线": "Offline",
    "ARM64 · 慢速回退": "ARM64 · slow fallback",
    "连接": "Connect",
    "最近在线": "Last seen",
    "添加后连接": "Connect after adding",
    "添加设备": "Add device",
    "已连接的 adb 设备会自动登记；离线设备会保留在列表中，可手动添加网络设备并连接。": "Connected adb devices are registered automatically; offline devices stay in the list, and network devices can be added and connected manually.",
    "无需填写即可添加：留空 Serial 会扫描并登记全部已连接设备；名称留空自动生成，裸 IP 自动补 5555 端口。删除仅从列表隐藏，不会断开 adb。": "No input required: leave Serial empty to scan and register all connected devices; the name is generated automatically and a bare IP gets port 5555. Delete only hides the device from the list; adb stays connected.",
    "留空自动扫描；也可填 127.0.0.1（自动补 5555）": "Leave empty to auto-scan; or enter 127.0.0.1 (port 5555 is added)",
    "留空自动命名": "Auto-named when empty",
    "设备已隐藏": "Device hidden",
    "没有发现新的在线设备": "No new online devices found",
    "没有发现模型，保留预设": "No models found; presets kept",
    "先保存模型再清空 Key": "Save the model before clearing the key",
    "API Key 已清空": "API key cleared",
    "Agent 已保存": "Agent saved",
    "Agent 已启用": "Agent enabled",
    "Agent 已停用": "Agent disabled",
    "Agent 已删除": "Agent deleted",
    "Skill 已保存": "Skill saved",
    "Skill 已删除": "Skill deleted",
    "MCP 已保存": "MCP saved",
    "MCP 测试失败": "MCP test failed",
    "MCP 已删除": "MCP deleted",
    "未发现设备": "No devices found",
    "切换到中文": "Switch to Chinese",
    "Agent 名称必填": "Agent name is required",
    "确认清空该模型的 API Key？": "Clear this model's API key?",
    "删除该模型？绑定的 Agent 也会被删除。": "Delete this model? Agents bound to it will also be deleted.",
    "删除该 Agent？": "Delete this Agent?",
    "删除该 Skill？": "Delete this Skill?",
    "删除该 MCP Server？已绑定它的 Agent 会失去该工具。": "Delete this MCP server? Agents bound to it will lose its tools.",
    "确认删除该任务及其 DEX、源码、证据、日志和运行目录？此操作不可恢复。": "Delete this task and its DEX, source, evidence, logs and run directory? This cannot be undone.",
    "输入新的密码（至少 4 位）": "Enter a new password (at least 4 characters)",
    "确认清理全部符合条件的已结束任务？删除后不可恢复。": "Clean all eligible finished tasks? This cannot be undone.",
    "确认清理全部符合条件的无引用上传？删除后不可恢复。": "Clean all eligible unreferenced uploads? This cannot be undone.",
    "确认清理全部符合条件的孤立运行目录？删除后不可恢复。": "Clean all eligible orphan run directories? This cannot be undone.",
    "确认清理全部符合条件的已结束任务、无引用上传与孤立运行目录？删除后不可恢复。": "Clean all eligible finished tasks, unreferenced uploads and orphan run directories? This cannot be undone.",
    "可选": "optional",
    "设备名称": "Device name",
    "备注": "Notes",
    "名称": "Name",
    "类型": "Type",
    "网络": "Network",
    "设备扫描失败": "Device scan failed",
    "Serial 必填": "Serial is required",
    "连接失败，请检查地址": "Connection failed; check the address",
    "设备已添加": "Device added",
    "设备已连接": "Device connected",
    "设备已更新": "Device updated",
    "设备已删除": "Device deleted",
    "无密钥": "no secrets",
    "未配置": "not configured",
    "已配置": "configured",
    "仅支持单个 .apk 文件": "Single .apk file only",
    "不支持的分卷包": "Unsupported bundle archive",
    ".apks / .xapk 是 APK 分卷包，后端不支持（bundle_not_supported）；请先转换为单个 .apk 文件。": ".apks / .xapk are APK bundle archives and are not supported (bundle_not_supported); convert them to a single .apk file first.",
    "高级任务选项": "Advanced job options",
    "冻结超时 ms": "Freeze timeout (ms)",
    "内存区域上限": "Memory region cap",
    "JADX 超时 s": "JADX timeout (s)",
    "总超时 s": "Total timeout (s)",
    "Frida Server 路径": "Frida server path",
    "强制 DEX dump": "Force DEX dump",
    "内层 SO 绕过": "Inner SO bypass",
    "清理原始 dump": "Prune raw dumps",
    "清理设备": "Clean device",
    "设备清理": "Device cleanup",
    "清理错误": "Cleanup error",
    "不完整": "Incomplete",
    "任务运行结束后才能清理设备": "The device can be cleaned after the task finishes",
    "清理该任务在设备上的转发、重命名库与临时文件（不卸载 APK）": "Clean this task's port forwards, renamed libraries and temp files on the device (the APK is not uninstalled)",
    "确认清理该任务在设备上留下的改动（端口转发、重命名库、frida-server、临时文件）？已安装的 APK 不会自动卸载。": "Clean the changes this task left on the device (port forwards, renamed libraries, frida-server, temp files)? The installed APK is not uninstalled automatically.",
    "设备清理完成": "Device cleanup complete",
    "设备清理不完整，请查看任务详情": "Device cleanup is incomplete; check the task details",
    "任务不存在或已删除，无法清理": "Task not found or deleted; cannot clean up",
    "当前后端尚未提供设备清理接口（cleanup_not_supported）": "This backend does not expose device cleanup yet (cleanup_not_supported)",
    "清理失败": "Cleanup failed",
    "ARM 可用性：加载中…": "ARM availability: loading…",
    "未检测到在线 ARM64 设备；勾选后任务会尝试自动准备 ARM64 redroid（QEMU 很慢），失败会返回 arm_runtime_unavailable，不会假装可用。": "No online ARM64 device detected. When selected, the task will try to provision ARM64 redroid automatically (QEMU is slow); failure returns arm_runtime_unavailable instead of pretending it is available."
  };

  const PATTERNS = [
    [/^共 (\d+) 个任务 · 每页 (\d+) 条$/, "$1 tasks · $2 per page"],
    [/^第 (\d+)[–-](\d+) 条 \/ 共 (\d+) 条$/, "Showing $1–$2 of $3"],
    [/^任务 (job_.+)$/, "Job $1"],
    [/^阶段：(.*)$/, "Stage: $1"],
    [/^管理员 (\d+) · 可用 (\d+)$/, "Admins $1 · active $2"],
    [/^自动 (\d+) · 手工 (\d+)$/, "Auto $1 · manual $2"],
    [/^自动 (\d+)$/, "Auto $1"],
    [/^手工 (\d+)$/, "Manual $1"],
    [/^总计 (\d+)$/, "Total $1"],
    [/^壳分布 (.*)$/, "Shell distribution: $1"],
    [/^共 (\d+) 个上传文件 · (.*)$/, "$1 uploaded files · $2"],
    [/^关联任务 (\d+)$/, "Linked jobs: $1"],
    [/^上传 (\d+) · 运行 (\d+) · 任务目录 (\d+)$/, "Uploads $1 · runs $2 · job dirs $3"],
    [/^可用 \/ 共 (.*)$/, "free / total $1"],
    [/^(.+) · (\d+) 条消息$/, "$1 · $2 messages"],
    [/^(.+) · (\d+) 条 · (.*)$/, "$1 · $2 messages · $3"],
    [/^(\d+) 条消息$/, "$1 messages"],
    [/^(\d+) 条 · (.*)$/, "$1 messages · $2"],
    [/^清理完成：任务 (\d+) · 上传 (\d+) · 运行目录 (\d+) · 释放 (.*)$/, "Cleanup: jobs $1 · uploads $2 · runs $3 · freed $4"],
    [/^同时删除 (\d+) 个任务$/, "$1 linked tasks deleted"],
    [/^上传已删除，同时删除 (\d+) 个任务$/, "Upload deleted; $1 linked tasks deleted"],
    [/^上传已删除$/, "Upload deleted"],
    [/^确认导入 (\d+) 条经验？只添加新经验，不覆盖已有经验。$/, "Import $1 lessons? Only new lessons are added; existing lessons are not overwritten."],
    [/^导入完成：新增 (\d+)，跳过 (\d+)，无效 (\d+)$/, "Import complete: $1 added, $2 skipped, $3 invalid"],
    [/^安装完成：新增 (\d+)，跳过 (\d+)，错误 (\d+)：(.*)$/, "Installation complete: $1 added, $2 skipped, $3 errors: $4"],
    [/^安装完成：新增 (\d+)，跳过 (\d+)$/, "Installation complete: $1 added, $2 skipped"],
    [/^附件 (.+) 超过 20 MB$/, "Attachment $1 exceeds 20 MB"],
    [/^上传附件 (\d+)\/(\d+)…$/, "Uploading attachment $1/$2…"],
    [/^任务已创建$/, "Task created"],
    [/^设备 (.*)$/, "Device $1"],
    [/^(.+) · 最近在线 (.*)$/, "$1 · last seen $2"],
    [/^(.+) · 离线$/, "$1 · offline"],
    [/^从设备登记表删除 (.+)？这不会断开 adb 连接。$/, "Delete $1 from the device registry? This does not disconnect adb."],
    [/^从设备列表隐藏 (.+)？这不会断开 adb，设备仍保持连接。$/, "Hide $1 from the device list? This does not disconnect adb; the device stays connected."],
    [/^已自动登记 (\d+) 台设备$/, "Auto-registered $1 devices"],
    [/^设备已更新：新增 (\d+) 台，恢复 (\d+) 台$/, "Devices updated: $1 added, $2 restored"],
    [/^设备已更新：新增 (\d+) 台$/, "Devices updated: $1 added"],
    [/^设备已更新：恢复 (\d+) 台$/, "Devices updated: $1 restored"],
    [/^确认删除上传文件 “(.*)”，并删除关联的 (\d+) 个任务及产物？此操作不可恢复。$/, "Delete upload \"$1\" and its $2 linked tasks/artifacts? This cannot be undone."],
    [/^确认删除上传文件 “(.*)”？此操作不可恢复。$/, "Delete upload \"$1\"? This cannot be undone."],
    [/^确认删除用户 “(.*)”？此操作不可恢复。$/, "Delete user \"$1\"? This cannot be undone."],
    [/^确认删除聊天 “(.*)”？聊天记录不可恢复。$/, "Delete chat \"$1\"? Chat history cannot be recovered."],
    [/^确认清理(\d+) 天前的已结束任务、无引用上传与孤立运行目录？删除后不可恢复。$/, "Clean finished tasks, unreferenced uploads and orphan run directories older than $1 days? This cannot be undone."],
    [/^确认清理(\d+) 天前的已结束任务？删除后不可恢复。$/, "Clean finished tasks older than $1 days? This cannot be undone."],
    [/^确认清理(\d+) 天前的无引用上传？删除后不可恢复。$/, "Clean unreferenced uploads older than $1 days? This cannot be undone."],
    [/^确认清理(\d+) 天前的孤立运行目录？删除后不可恢复。$/, "Clean orphan run directories older than $1 days? This cannot be undone."],
    [/^连接成功 · (\d+)ms$/, "Connected · $1ms"],
    [/^连接失败：(.*)$/, "Connection failed: $1"],
    [/^发现 (\d+) 个模型$/, "$1 models found"],
    [/^MCP 连接成功，(\d+) 个工具$/, "MCP connected · $1 tools"],
    [/^已配置：(.*)（留空不修改）$/, "Configured: $1 (leave blank to keep)"],
    [/^已配置：(.*)$/, "Configured: $1"],
    [/^已有: (.*)（留空保持不变）$/, "Existing: $1 (leave blank to keep)"],
    [/^编辑模型 · (.*)$/, "Edit model · $1"],
    [/^编辑 Agent · (.*)$/, "Edit Agent · $1"],
    [/^调用 (.*)$/, "Call $1"],
    [/^MCP 结果 (.*)$/, "MCP result $1"],
    [/^结果 (.*)$/, "Result $1"],
    [/^统计加载失败：(.*)$/, "Failed to load statistics: $1"],
    [/^存储统计加载失败：(.*)$/, "Failed to load storage statistics: $1"],
    [/^(.*) 不是合法 JSON$/, "$1 is not valid JSON"],
    [/^(.*) 必须是 JSON 对象$/, "$1 must be a JSON object"],
    [/^Base URL 必填$/, "Base URL is required"],
    [/^成功 (\d+)\/(\d+) \((.*)\) · 最近 (.*)$/, "Success $1/$2 ($3) · last $4"],
    [/^场景：(.*)$/, "Scenario: $1"],
    [/^根因：(.*)$/, "Root cause: $1"],
    [/^解法：(.*)$/, "Solution: $1"],
    [/^症状：(.*)$/, "Symptoms: $1"],
    [/^失败方法：(.*)$/, "Failed methods: $1"],
    [/^框架：(.*)$/, "Framework: $1"],
    [/^证据：(.*)$/, "Evidence: $1"],
    [/^人工编辑：(.*)$/, "Edited: $1"],
    [/^已选择 (\d+) 条经验$/, "$1 lessons selected"],
    [/^确认删除经验 “(.*)”？此操作不可恢复。$/, "Delete lesson \"$1\"? This cannot be undone."],
    [/^确认删除选中的 (\d+) 条经验？此操作不可恢复。$/, "Delete $1 selected lessons? This cannot be undone."],
    [/^已删除 (\d+) 条经验$/, "Deleted $1 lessons"],
    [/^关联任务 (\d+)$/, "Linked jobs: $1"],
    [/^已检测到在线 ARM64 设备：(.*)；勾选后优先使用（QEMU 较慢）。 注意：最近任务报告 ARM64 运行时不可用：(.*)$/, "Online ARM64 device(s): $1; preferred when selected (QEMU is slow). Note: the last task reported the ARM64 runtime unavailable: $2"],
    [/^已检测到在线 ARM64 设备：(.*)；勾选后优先使用（QEMU 较慢）。$/, "Online ARM64 device(s): $1; preferred when selected (QEMU is slow)."],
    [/^注意：最近任务报告 ARM64 运行时不可用：(.*)$/, "Note: the last task reported the ARM64 runtime unavailable: $1"],
    [/^ARM64 运行时最近报告不可用：(.*)。仍可勾选，但准备失败会明确返回 arm_runtime_unavailable。$/, "The ARM64 runtime was recently reported unavailable: $1. You can still select it, but preparation will fail explicitly with arm_runtime_unavailable."],
    [/^设备清理完成（已恢复 (\d+) 项）$/, "Device cleanup complete ($1 restored)"],
    [/^设备清理不完整，请查看任务详情（已恢复 (\d+) 项）$/, "Device cleanup is incomplete; check the task details ($1 restored)"],
    [/^当前无法清理：(.*)$/, "Cannot clean up now: $1"],
    [/^(.+) 必须是非负数字$/, "$1 must be a non-negative number"]
  ];

  const OBSERVE = { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ["placeholder", "title", "aria-label"] };
  const TEXT_SKIP = "script,style,textarea,[data-no-i18n],.events,.pre,.chat-message-body,.chat-tool,.job-file,.upload-name";
  const ATTR_SKIP = "[data-no-i18n],.events,.pre,.chat-message-body,.chat-tool,.job-file,.upload-name";
  const textOriginals = new WeakMap();
  const attrOriginals = new WeakMap();
  let lang = localStorage.getItem("apu_lang") || "zh";
  let observer = null;
  let scheduled = false;

  function preserveWhitespace(original, trimmed, replacement) {
    const start = original.match(/^\s*/)[0];
    const end = original.match(/\s*$/)[0];
    return start + replacement + end;
  }

  function translateText(value) {
    const trimmed = value.trim();
    if (!trimmed) return null;
    if (Object.prototype.hasOwnProperty.call(EN, trimmed)) return EN[trimmed];
    for (const [pattern, replacement] of PATTERNS) {
      if (pattern.test(trimmed)) return trimmed.replace(pattern, replacement);
    }
    let changed = trimmed
      .replace(/阶段：/g, "Stage: ")
      .replace(/关联任务 /g, "Linked jobs: ")
      .replace(/设备 /g, "Device ")
      .replace(/成功 (\d+)\/(\d+) \((\d+)%\) · 最近 /g, "Success $1/$2 ($3%) · last ")
      .replace(/场景：/g, "Scenario: ")
      .replace(/根因：/g, "Root cause: ")
      .replace(/解法：/g, "Solution: ")
      .replace(/症状：/g, "Symptoms: ")
      .replace(/失败方法：/g, "Failed methods: ")
      .replace(/框架：/g, "Framework: ")
      .replace(/证据：/g, "Evidence: ")
      .replace(/(\d+) 条消息/g, "$1 messages")
      .replace(/(\d+) 条 ·/g, "$1 messages ·")
      .replace(/(\d+) 个任务/g, "$1 tasks")
      .replace(/(\d+) 个上传文件/g, "$1 uploaded files")
      .replace(/OpenAI 协议/g, "OpenAI protocol")
      .replace(/Anthropic 协议/g, "Anthropic protocol")
      .replace(/OpenAI 兼容/g, "OpenAI compatible")
      .replace(/自动兼容/g, "Auto compatible")
      .replace(/ · 输出 /g, " · Output ")
      .replace(/确定性工作流/g, "Deterministic workflow")
      .replace(/Deterministic workflow · deterministic workflow/g, "Deterministic workflow")
      .replace(/APK 脱壳[（(]内置[）)]/g, "APK unpacking (built-in)")
      .replace(/无密钥/g, "no secrets")
      .replace(/key 未配置/g, "key not configured")
      .replace(/key 已配置/g, "key configured")
      .replace(/360加固/g, "360 Jiagu")
      .replace(/腾讯加固/g, "Tencent MTP")
      .replace(/爱加密/g, "Ijiami")
      .replace(/梆梆/g, "Bangcle")
      .replace(/脱壳/g, "unpacking")
      .replace(/加固/g, "hardening")
      .replace(/\(当前\)/g, "(current)")
      .replace(/（当前）/g, "(current)")
      .replace(/最近在线/g, "last seen")
      .replace(/（任意 URL）/g, " (any URL)")
      .replace(/（确定性）/g, " (deterministic)")
      .replace(/（可多选）/g, " (multi-select)")
      .replace(/（/g, "(")
      .replace(/）/g, ")")
      .replace(/Auto compatible\(/g, "Auto compatible (")
      .replace(/不可用/g, "unavailable")
      .replace(/天前的/g, "days ago")
      .replace(/全部符合条件的/g, "all eligible");
    return changed !== trimmed ? changed : null;
  }

  function shouldSkip(node, selector) {
    const parent = node.nodeType === Node.ELEMENT_NODE ? node : node.parentElement;
    if (!parent) return true;
    try {
      return Boolean(parent.closest(selector));
    } catch (e) {
      return true;
    }
  }

  function translateTextNode(node) {
    if (!node.nodeValue || !/[一-鿿]/.test(node.nodeValue)) return;
    if (shouldSkip(node, TEXT_SKIP)) return;
    const original = node.nodeValue;
    const existing = textOriginals.get(node);
    if (existing && original === existing.en && !/[一-鿿]/.test(original)) return;
    let translated = translateText(original);
    if (!translated) return;
    let replacement = preserveWhitespace(original, original.trim(), translated);
    if (/[一-鿿]/.test(replacement)) {
      const second = translateText(replacement);
      if (second && second !== replacement) {
        replacement = preserveWhitespace(replacement, replacement.trim(), second);
      }
    }
    const zh = existing?.zh && /[一-鿿]/.test(existing.zh) ? existing.zh : original;
    textOriginals.set(node, { zh, en: replacement });
    node.nodeValue = replacement;
  }

  function translateAttr(element, name) {
    const value = element.getAttribute(name);
    if (!value || !/[一-鿿]/.test(value)) return;
    if (shouldSkip(element, ATTR_SKIP)) return;
    let store = attrOriginals.get(element);
    if (!store) {
      store = {};
      attrOriginals.set(element, store);
    }
    const existing = store[name];
    if (existing && value === existing.en) return;
    const translated = translateText(value);
    if (!translated) return;
    store[name] = { zh: value, en: translated };
    element.setAttribute(name, translated);
  }

  function walk(root) {
    if (!root) return;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) translateTextNode(walker.currentNode);
    if (root.querySelectorAll) {
      for (const element of root.querySelectorAll("*")) {
        for (const name of ["placeholder", "title", "aria-label"]) translateAttr(element, name);
      }
    }
  }

  function restore(root) {
    if (!root) return;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) {
      const node = walker.currentNode;
      const value = textOriginals.get(node);
      if (value && node.nodeValue === value.en) {
        node.nodeValue = value.zh;
        textOriginals.delete(node);
      }
    }
    if (root.querySelectorAll) {
      for (const element of root.querySelectorAll("*")) {
        const store = attrOriginals.get(element);
        if (!store) continue;
        for (const [name, value] of Object.entries(store)) {
          if (element.getAttribute(name) === value.en) element.setAttribute(name, value.zh);
        }
        attrOriginals.delete(element);
      }
    }
  }

  function apply() {
    if (lang !== "en") return;
    if (scheduled) return;
    scheduled = true;
    setTimeout(() => {
      scheduled = false;
      if (observer) observer.disconnect();
      try {
        walk(document.body, "en");
      } finally {
        if (observer) {
          observer.observe(document.body, OBSERVE);
        }
      }
    }, 20);
  }

  function setLanguage(next) {
    const target = next === "en" ? "en" : "zh";
    if (observer) observer.disconnect();
    restore(document.body);
    lang = target;
    document.documentElement.lang = target === "en" ? "en" : "zh-CN";
    localStorage.setItem("apu_lang", target);
    if (target === "en") walk(document.body, "en");
    if (observer) observer.observe(document.body, OBSERVE);
    window.dispatchEvent(new CustomEvent("apu:langchange", { detail: { lang: target } }));
  }

  function init() {
    document.documentElement.lang = lang === "en" ? "en" : "zh-CN";
    if (lang === "en") walk(document.body, "en");
    observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        if (mutation.type === "characterData" || mutation.type === "attributes") {
          if (lang === "en") apply();
          return;
        }
        if (mutation.addedNodes && mutation.addedNodes.length) {
          if (lang === "en") apply();
          return;
        }
      }
    });
    observer.observe(document.body, OBSERVE);
  }

  window.ApuI18n = {
    get lang() { return lang; },
    setLanguage,
    apply,
    translateText,
  };
  init();
})();
