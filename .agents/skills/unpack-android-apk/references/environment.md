# 设备与工具环境

## adb / 模拟器

```bash
adb devices -l
adb connect 127.0.0.1:62001    # 夜神常见端口：62001/62025/62026/62027/7555
adb root
adb shell id                   # 需要 uid=0
adb shell getprop ro.product.cpu.abi
adb shell getprop ro.product.cpu.abilist
adb shell getprop ro.build.version.sdk
```

- 夜神端口在重启后可能漂移；先 `adb devices`，不要硬编码。
- Windows 上夜神自带 `nox_adb.exe` 可能与 SDK 的 adb 冲突：
  结束 `nox_adb.exe`，`adb kill-server`，`adb start-server`。
- Git Bash 会把 `/data/local/tmp` 等路径改写；本工具用 Python subprocess，
  不经过 Git Bash，避免该问题。手工操作时用 PowerShell 或
  `MSYS_NO_PATHCONV=1`。

## frida-server

```bash
adb push frida-server /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell "setsid /data/local/tmp/frida-server -l 0.0.0.0:27042 >/dev/null 2>&1 < /dev/null &"
adb forward tcp:27042 tcp:27042
frida-ps -H 127.0.0.1:27042
```

- 版本必须与 PC 上的 `frida --version` 一致（本项目实战环境为 17.8.2）。
- 架构必须与设备 ABI 一致（x86_64 设备用 x86_64 server）。
- 夜神上 `nohup` / `su -c` 可能 exit 127；用 `setsid ... < /dev/null &`。
- 用 `APU_FRIDA_SERVER` 指定本地二进制，`prepare_android_environment` 会自动 push。
- 只 kill 本次 run 启动的 PID；不要 `killall frida-server`。

## aapt / jadx / Java

- aapt：优先 `APU_AAPT`；本机默认尝试
  `C:\Program Files (x86)\Nox\bin\aapt.exe`。
- jadx：`APU_JADX_JAR` 或工作区 `jadx\lib\jadx-gui-1.5.5-all.jar`。
- Java：`APU_JAVA` / `JAVA_HOME` / PATH / 工作区内置 JRE。
- jadx 必须以 CLI 类启动，不要用 `-jar`（会进 GUI）：
  ```
  java -Xmx4G -cp <jadx-gui-all.jar> jadx.cli.JadxCLI --no-res --no-debug-info -d out classes*.dex
  ```
- jadx 缓存：`%LOCALAPPDATA%\skylot\jadx\cache`；修复重试仍报同样错误时清理。

## ABI / Houdini

```bash
unzip -l "$APK_PATH" | grep "lib/" | awk -F/ '{print $2}' | sort -u
```

- APK 只有 ARM、设备是 x86_64 → 通过 Houdini/native-bridge 翻译运行。
- 证据：`/proc/<pid>/maps` 出现 `/system/vendor/lib64/arm64/nb/` 或 `libhoudini.so`。
- 这类 App 常 1–3 秒崩溃；优先 `freeze_dd` 或 `bs=1024` 快速 dd。
- 壳自身的 `assets/ijm_lib/x86_64/libexec.so` 可能仍是原生 x86_64，能正常解密。

## Frida 17.x API

| 目标 | 17.x |
|---|---|
| 模块 | `Process.getModuleByName("libc.so")` |
| 导出 | `module.getExportByName("exit")` |
| 全局导出 | `Module.getGlobalExportByName("open")` |
| 读内存 | `Memory.readByteArray(ptr, n)`（堆地址可能失败） |
| 枚举内存 | `Process.enumerateRanges({protection:'r--'})` |
| Java 数组长度 | `java.lang.reflect.Array.getLength(arr)` |
| DexFile.entries | `Java.cast(dex, DexFileClass).entries()` |
| spawn | `-f` 自动 resume；`--no-pause` 已移除 |

## Windows 注意

- 路径含中文/空格：本工具的 Python subprocess 用 argv 列表，不做 shell 拼接；
  Frida wrapper 复制到 ASCII 临时目录。
- PowerShell `$PID` 是保留变量，手工脚本用 `$appPid`。
- `adb exec-out` 是二进制输出；不要用文本模式解码。
- 手工用 `adb pull/push` 时优先 PowerShell，避免 Git Bash 路径改写。

## 权限与前提

- `memory_dd` / `freeze_dd` 需要 root。
- `disk_pull` 在非 root 时可尝试 `run-as <pkg> cat <path>`（仅 debuggable）。
- 安装 APK 需要显式 `allow_install=true`；不会自动卸载。

## Docker 迁移中的分层检查

- 不能只对比 x86/ARM：同时记录 Android SDK、实际 native bridge、壳选中的 ELF、
  进程退出阶段以及已读出的业务类证据。
- ARM64 QEMU 后备环境需要分别验证容器入口、Android 完成启动、ADB root 重启后
  仍可连接、目标进程身份以及 DEX；前一层成功不代表后一层成功。
- 项目兼容配置修复 Binder 空载荷越界、嵌套指针标签、netd 所需 netlink 协议、
  `SO_MARK` 和 64 位 `SO_COOKIE`。binfmt 的 `F` 标志会保留旧解释器文件，更新后
  必须刷新同一 ARM64 注册项，不能只比较路径。
- QEMU 的辅助线程不属于 Android 线程；兼容配置按 guest `TaskState.ts_tid`
  提供自身 task 列表，避免 Zygote 在 fork 前无限等待。
- QEMU 进程的内核 cmdline 可能保留解释器参数。此时工具通过 ActivityManager 的
  完整进程名、QEMU 包装命令和内核 comm 交叉确认 PID；禁止用包名前缀猜 PID。
- 业务 `Application.onCreate` 已执行后出现缺少系统服务的 Java 异常，说明应先
  检查 Android 服务依赖并尝试崩溃前抓取，不能一律归因于壳未解密或反调试。
