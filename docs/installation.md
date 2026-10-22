# 安装

## 前提

- Python 3.10+（本机 3.12）；**不需要任何第三方 Python 包**。
- adb（设备操作）。
- frida CLI 与设备端 frida-server，版本一致、架构匹配。
- 可选：aapt（manifest 静态解析）、Java + jadx all-in-one jar（反编译）。

本工具**不会**安装或升级这些外部工具。

## 直接运行

```powershell
cd apk-unpack-agents
$env:PYTHONPATH = "$PWD\src"
python -m apk_unpack doctor
```

或：

```powershell
.\apu.cmd doctor
```

## 可选：pip 安装

```powershell
python -m pip install -e .
apk-unpack doctor
```

安装后在任意目录可用 `apk-unpack` / `apu`；若 `src` 不在环境里，pip 会把它
加入包路径。不安装也可以直接用 `PYTHONPATH`。

## 工具解析顺序

| 工具 | 环境变量 | 默认 |
|---|---|---|
| adb | `APU_ADB` | PATH |
| frida | `APU_FRIDA` | PATH |
| frida-ps | `APU_FRIDA_PS` | PATH |
| frida-server | `APU_FRIDA_SERVER` | 工作区 `frida-server` |
| 经验记忆目录 | `APU_MEMORY_DIR` | `%LOCALAPPDATA%\apk-unpack\memory` |
| aapt | `APU_AAPT` | PATH / 夜神目录 |
| java | `APU_JAVA` / `JAVA_HOME` | PATH / 工作区 `jadx\jre` |
| jadx jar | `APU_JADX_JAR` | 工作区 `jadx\lib\jadx-gui-*-all.jar` |

## 安装为 Claude Code Agent

```powershell
# 1) 预览：显示将要复制的 skill、要合并的 .mcp.json、备份路径
python -m apk_unpack setup --project-dir .

# 2) 确认后应用
python -m apk_unpack setup --project-dir . --yes
```

默认行为：

- 复制 `.agents/skills/unpack-android-apk/` 到 `~/.claude/skills/unpack-android-apk/`
  （已有目录会先备份为 `.apu.bak-<时间戳>`）；
- 合并项目 `.mcp.json` 的 `mcpServers.apk-unpack`，保留其他键；
- 写入 `.apu-managed.json` 以便卸载时只删除本工具拥有的内容；
- 不修改 `~/.claude.json` 等其他用户配置。

通用客户端：

```powershell
python -m apk_unpack setup --client generic
```

会打印 MCP 配置片段，不写任何文件。

卸载：

```powershell
python -m apk_unpack setup --project-dir . --yes --uninstall
```

只会删除带 `.apu-managed.json` 的 skill 目录和 `mcpServers.apk-unpack` 条目。

## doctor

```powershell
python -m apk_unpack doctor --json
```

检查：Python、adb、frida CLI、frida-server 本地文件、aapt、Java、jadx jar、
运行目录可写、经验记忆目录可写、设备连接/root/frida reachability。
每项失败都给出 remediation。

## 设备准备（手工）

1. 启动模拟器/连接设备，`adb devices -l` 可见。
2. `adb root` 后 `adb shell id` 为 uid=0。
3. 推送匹配架构的 frida-server，`setsid ... &` 启动，forward 27042。
4. 用 `APU_FRIDA_SERVER` 指向本地二进制，或 `prepare --frida-server <path>`
   让工具自动 push/启动。

## 测试

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m unittest discover -s tests -v
```

真机测试：

```powershell
$env:APU_DEVICE_TESTS = "1"
python -m unittest discover -s tests -v
```

无设备时，Frida/dd 真机链路标记为未验证；静态检测、DEX 修复/验证、策略、
MCP/CLI 可离线验证。
