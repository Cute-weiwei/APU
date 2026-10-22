# 路由：先看目标，再选工具

## 顺序

1. **`inspect_apk`**：永远是第一步。输出包含：
   - package / version / launchable activity / application / appComponentFactory
   - DEX 顶层 header（`class_defs_size`、`file_size`、加密尾部字节）
   - ABI、框架（uni-app / Flutter / React Native）
   - 壳层（`packing.primary`、`layers`、`mixed`、`precedence_notes`）
   - Coverage 与 limitations
2. **`recommend_unpack_strategy`**：基于壳层、ABI、设备与进程事实给出：
   - `primary`：首选 dump 方法
   - `fallbacks`：有序回退链
   - `do_not_attempt`：明确禁止的路线
   - `prerequisites` / `risks` / `notes`
3. 若 `frameworks` 含 `uni-app` 且存在 `assets/__UNI__*.wgt`：
   - 调 `extract_apk_assets` 静态提取，优先结束；不要默认动态脱壳。
4. 若要动态脱壳：
   ```
   inspect_android_device
     → prepare_android_environment（目标未安装时 allow_install=true）
     → launch_android_target
     → inspect_process_state
     → dump_android_dex (method=auto)
     → repair_android_dex
     → verify_android_dex
     → decompile_android_apk (可选)
     → cleanup_run
   ```
   - 新 APK 用 `unpack --install`，或 `prepare_android_environment` 传
     `apk_path` + `allow_install=true`。
   - base + 同包 `split_*.apk` / `config.*.apk` 会自动用 `install-multiple`。
   - `.apks` / `.xapk` 不能直接 inspect；先解出 base APK，或在已有 run 上用
     `prepare --apk bundle --allow-install` 安装。

## 每次平台操作前确认

- 设备在线且有 root（`inspect_android_device.root.available`）。
- Frida CLI 版本与 frida-server 版本一致（`frida.version_matches`）。
- `frida.reachable` 为 true；否则先 `prepare_android_environment`。
- APK 的 ABI 与设备是否匹配；仅 ARM 的包在 x86/x86_64 上通常走 Houdini，崩溃窗口很短。
- 目标进程是否 `TracerPid != 0`（attach 可能被 ptrace 挡住）。

## 输出优先摘要

`inspect_apk` / `inspect_process_state` / `dump_android_dex` 的返回可能较大。
先用返回的摘要和 Evidence；需要完整记录时用 `get_evidence` 或
`export_evidence_bundle`，不要重复调用同一工具。

## 何时停止

- Bangcle：最多一次 Frida 尝试，随后直接 dd。
- 360：不要用 dd 代替 mCookie；TracerPid 非 0 时最多一次 spawn+anti-kill。
- 自毁型：不要在固定 sleep 后 dump；应轮询 maps 并 SIGSTOP。
- 同一个失败方法不要重试超过一次；换策略或报告阻塞。
