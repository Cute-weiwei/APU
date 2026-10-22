# 策略决策树

## 总原则

1. 先静态，再动态；先低风险，再注入/读内存。
2. 同一个壳的不同 APK 反调强度不同；**永远保留回退链**，不要假设 attach 或 spawn 一定可用。
3. 识别错壳是最大坑。壳类型优先于“看起来很稳定”。
4. 每条失败路径最多重试一次；之后换策略或报告阻塞。

## 决策树

```
inspect_apk
├─ uni-app + __UNI__*.wgt
│    → extract_apk_assets（静态，优先结束）
├─ packed=false 且 shell=unknown
│    → decompile_android_apk（普通 APK，无需脱壳）
├─ libDexHelper（Bangcle，含混合壳）
│    → prepare(root) → launch → inspect_process_state
│    → dump_android_dex(method=memory_dd)
│    → 失败回退 memory_dd_retry（重新启动 + fast bs 快速 dd）
│    → 再回退 freeze_dd（已泛化为等待 libc_malloc/[heap]）
│    → 禁止：frida_inmemory / frida_inmemory_spawn / frida_mcookie
├─ 360（libjiagu/libjgdtc/StubApp）
│    ├─ 内层 SecNeo（静态 libSdkHelper 或崩溃栈）
│    │    → prepare(inner_bypass=true) → launch → attach
│    │    → dump_android_dex(method=frida_mcookie)
│    ├─ TracerPid=0
│    │    → dump_android_dex(method=frida_mcookie)
│    └─ TracerPid≠0
│         → 让 method=auto 走策略里的 frida_mcookie_spawn_anti_kill
│           （显式 mode=spawn 不会自动装 anti-kill hook）
│         → 仍失败 → 报告 ARM64 真机回退
│    → 禁止：memory_dd（360 的 DEX 不在可扫区域）
├─ 腾讯 MTP（libshell-super/0OO00l）
│    → prepare → launch → attach
│    → dump_android_dex(method=disk_pull)
│    → 回退 frida_inmemory
├─ ijiami（ijiami.dat / s.h.e.l.l.*）
│    → prepare → launch → inspect_process_state
│    → dump_android_dex(method=frida_inmemory)
│    → 回退 frida_inmemory_spawn（spawn + anti-kill，一次）
│    → 再回退 memory_dd（dalvik-DEX）
│    → 自毁/短窗口 → freeze_dd（15s 轮询，PID 死亡会重新查找）
└─ unknown
     → attach 一次 → spawn 一次 → memory_dd → freeze_dd
```

## 各方案要点

### Frida in-memory / cookie

- 适合：ijiami、360、MTP 的初始尝试。
- 关键：`Java.cast(dex, DexFileClass)` 后再 `entries()`；mCookie 遍历全部指针。
- 失败信号：进程秒退、无 `hello`、`done` 为 false、没有任何 `saved`。
- 对 inline syscall 自杀无效；不要反复 hook `exit`。

### 磁盘 pull（MTP）

- Frida 读取 ClassLoader 路径，或直接列 `files/prodexdir`。
- 解密 DEX 已落盘，header/checksum 完整，通常无需修复。
- 占位 `classes2/3.dex` 不是真代码。

### `/proc/pid/mem` dd（Bangcle / 兜底）

- 零注入、零 ptrace，绕过大多数反调试。
- Bangcle 目标区：`[anon:libc_malloc]` / `[heap]`。
- ijiami 目标区：`/dev/ashmem/dalvik-DEX`（或 `dalvik-DEX data`）。
- 必须按 header `file_size` dump；跨 mmap 要分段拼接。
- 稳定运行用 `bs=1`；崩溃窗口用 `bs=1024` 快速 dump。

### ijiami 模拟器检测库（Houdini 崩溃循环）

- 典型现象：ARM-only APK 在 x86/x86_64 模拟器上启动后 1–3 秒进程死亡并循环重启，
  `am start -W` 可能返回非零。
- `launch_android_target` 默认会自动（且可逆地）重命名目标包内的
  `libijm-emulator.so` / `libijmdetect-drisk.so`，然后重试一次；改动记录在
  `mutations.json`，`cleanup_run` 会恢复。
- 需要保留现场或手动控制时用 `--no-auto-bypass`，再通过
  `prepare --rename-lib ...` 显式操作。
- 只会在目标包自己的安装目录内搜索，绝不会扫全 `/data/app` 误改其它应用。

### SIGSTOP 冻结 + dd（自毁型）

- 轮询 maps 直到出现 `dalvik-DEX`（80ms 间隔），立即 `kill -STOP`。
- 验证 `/proc/<pid>/status` 的 `State: T`。
- dump 后必须 `kill -CONT`；清理流程也会补发。

## 禁止项与原因

| 禁止 | 原因 |
|---|---|
| Bangcle 反复 Frida | fake_dlsym + 0xdead0000 + inline syscall，基本全灭 |
| 360 用 dd 代替 mCookie | DEX 经多个 native DexFile* 引用，内存中无连续可扫 magic |
| 自毁 App 固定 sleep | 解密完成时间抖动 0.24–1.8s，必须轮询 maps |
| 重打包 APK 注入 gadget | 签名校验/崩溃；改用设备侧重命名/注入 |
| 盲目 NOP `0f 05` | 编码被混淆，误伤系统库会崩 ART verifier |
| 复制“扫 libc_malloc”到 ijiami | ijiami 的 DEX 在 dalvik-DEX ashmem，不在 libc_malloc |

## 失败后的下一次动作

| 失败 | 下一次 |
|---|---|
| attach 被 SIGKILL | spawn + anti-kill 一次；仍失败转 dd |
| spawn 秒退 | attach；若进程仍活；否则 dd/freeze |
| Frida 无 saved | 检查 `ready`/`candidate` 事件；换 dd |
| dd 区域全零 | 换区域（dalvik-DEX / libc_malloc） |
| dd I/O error | 降 bs（4096→1024→64→1）或缩短单次范围 |
| DEX 截断 | 按 file_size 跨 mmap 重读；或 freeze 后重试 |
| 360 attach 失败 | 检查 TracerPid；内层 SecNeo；ARM64 真机 |

## 当前不覆盖 / 需换工具的场景

| 场景 | 说明 |
|---|---|
| Flutter 业务逻辑 | 通常在 `lib/<abi>/libapp.so`，DEX dump 拿不到；需要 blutter/Flutter 专用工具 |
| React Native 业务逻辑 | 通常在 `assets/index.android.bundle`；DEX 可能只有宿主壳 |
| Split APK / App Bundle | 本工具不自动合并 base + split；需先组装完整 APK |
| 内核/虚拟化级反调试 | 用户态 Frida/dd 无法稳定绕过；需要内核模块或真机专门方案 |
| Android 10+ 的 DexFile 结构差异 | 脚本只探测 `+0x08/+0x10` 与 `+0x10/+0x18`；其他布局会报告 unknown，不伪造成功 |
| 非 root 设备 | frida-server 注入和 `/proc/pid/mem` 不可用；仅 run-as/可调试应用有有限可能 |
