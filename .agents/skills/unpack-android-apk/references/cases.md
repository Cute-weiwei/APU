# 12 篇实战案例矩阵

| # | 案例 | 壳 | ABIs / 设备 | 关键现象 | 最终方案 | 关键坑 |
|---|---|---|---|---|---|---|
| 1 | 样本01 | ijiami | x86_64 + ARM / x86_64 模拟器 | 不稳定，spawn 秒死 | 绕过检测后 attach + `Java.cast().entries()` | 只拿到类名，不是 DEX 字节 |
| 2 | 样本02 | ijiami | x86_64 + ARM / x86_64 | 稳定但 attach SIGKILL | spawn + anti-kill + `NativeFunction(fwrite)` | inline syscall 自杀 |
| 3 | 样本03 | ijiami | 仅 ARM / x86_64 Houdini | 稳定，双进程 ptrace | `/proc/pid/mem` 精确 dd `dalvik-DEX` | DEX 不在 libc_malloc |
| 4 | 样本04 | ijiami | 仅 ARM / x86_64 | 1.5s 自毁，PID 变化 | SIGSTOP 冻结 + dd `dalvik-DEX data` | 固定 sleep 不可靠 |
| 5 | 样本05 | 梆梆 + ijiami | x86_64 + ARM | Frida 全灭 | root dd `libc_malloc` | 误按纯 ijiami 处理 |
| 6 | 样本06 | 梆梆 | 仅 ARM / x86_64 | Frida 全免疫 | 快速 dd | 只提取到部分 DEX，需复扫 |
| 7 | 样本07 | 梆梆 | 仅 ARM / x86_64 | 2.7s 崩溃 | `bs=1024` 崩溃窗口 dd | 崩溃窗口约 2.5s |
| 8 | 样本08 | 腾讯 MTP | x86_64 + ARM | attach 可用 | ClassLoader → 磁盘 `prodexdir` → pull | 占位 classes2/3.dex |
| 9 | 样本09 | 360 | x86_64 + ARM | 新版 360 反调试强 | Frida mCookie | dd 对 360 无效 |
| 10 | 样本10 | 360 | x86_64 + ARM | TracerPid=0，attach 可用 | attach + mCookie 多指针 | cookie 长度 5，不只 cookie[1] |
| 11 | 样本11 | 360 外层 + SecNeo 内层 | 仅 ARM / x86_64 | 首启 SIGABRT | 重命名 `libSdkHelper_sdk.so` → attach → mCookie | 内层库静态不显眼 |
| 12 | 样本12 | 梆梆 | 仅 ARM | Frida 全免疫 | dd | 漏 DEX 需按 magic 命中数核对 |

## 跨案例结论

1. **同一个壳，不同 APK 的反调强度不同**。不要用一个案例的 attach/spawn 结果
   推断另一个 APK。
2. **识别错壳 = 策略全错**。`libDexHelper` 出现时按 Bangcle；360 用 mCookie；
   MTP 用磁盘 pull。
3. **ijiami 的 DEX 位置随场景变化**：可能在 InMemoryDexFile、dalvik-DEX
   ashmem，甚至需要冻结后才能看到 `dalvik-DEX data`。
4. **dd 的参数决定成败**：区域、bs、file_size、跨 mmap、冻结时机。
5. **Frida 的盲区是 inline syscall**：libc hook 对 Bangcle/新版 360 无效。
6. **完整性要脚本化核对**：magic 命中数 == 提取数，不能人工数。
7. **不要重打包 APK**：签名校验会直接失败；设备侧可逆改名更可靠。

## 参考量级

- DEX 数量：3–15
- 总类数：3.6 万–6.8 万
- 应用类：1,400–4,600
- Java 文件：1.8 万–3.3 万

这些数字只用于判断“是不是只拿到了壳”，不是验收标准。
