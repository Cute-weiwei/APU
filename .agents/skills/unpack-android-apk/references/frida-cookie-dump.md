# Frida cookie / in-memory dump

## 宿主如何驱动

本工具没有 Python Frida bindings，直接驱动 `frida` CLI：

```
frida -H 127.0.0.1:27042 -p <pid> -l <wrapper>.js -q   # attach
frida -H 127.0.0.1:27042 -f <package> -l <wrapper>.js -q  # spawn
```

- wrapper = `preamble.js` + `dump_cookie.js` + 内嵌 JSON 配置。
- wrapper 写到 ASCII 临时目录（`%TEMP%\apu\<run_id>`），规避中文路径。
- 脚本只输出 `APU::<json>` 行；宿主忽略其他输出。
- 事件类型：`hello` → `ready` → `candidate` → `saved` → `done`。
- 收到 `done` 后宿主终止 frida CLI；attach 模式下 App 继续运行，spawn 模式下
  被启动的进程会结束，这会在 Evidence 中注明。
- 默认超时 180s，硬超时由脚本内部 `setTimeout` 兜底。

## mCookie 结构

`DexFile.mCookie` 是 `long[]`，长度不固定：

| 场景 | cookie 长度 | 说明 |
|---|---|---|
| MTP / ijiami | 2 | `cookie[1]` 为单个 native DexFile* |
| 360 旧版 | 5 | `cookie[1..4]` 为多个 DexFile* |
| 360 双层 | 12 | `cookie[1..11]` |

脚本遍历 `1..len-1`（长度为 1 时也尝试 `0`），逐个探测：

- Android 9 x86_64：`+0x08` = `begin_`，`+0x10` = `size_`
- Android 8 变体：`+0x10` = `begin_`，`+0x18` = `size_`
- 脚本还会探测 `+0x00/+0x08`、`+0x18/+0x20`、`+0x20/+0x28`，只有 magic
  与 size 都合理时才接受；其他布局会报告 unknown，不伪造成功。

只有 `begin_` 前 4 字节为 `64 65 78 0a`（`dex\n`）且 `size_` 在
`112..512MiB` 时才写出。不要只读 `cookie[1]`，否则会漏 3–10 个 DEX。

## 写文件

不走 `Memory.readByteArray`（在部分 x86_64 `libc_malloc` 地址上会失败），
而是用目标进程自己的 libc：

```js
fopen / fwrite / fclose via NativeFunction
```

输出目录为 App 私有目录：

```
/data/user/0/<package>/files/apu/<run_id>/
```

宿主在 `done` 后 `adb pull` 并校验文件大小；默认删除设备端目录，除非
`keep_device_files=true`。如果 root pull 被拒，可尝试 `run-as` / `exec-out cat`。

## ClassLoader 枚举

- 优先 `Java.enumerateClassLoadersSync()`。
- 同时加入 `app.getClassLoader()` 和 manifest 的 launchable activity 的 loader。
- 对每个 `BaseDexClassLoader` 反射：
  `pathList` → `dexElements` → `Element.dexFile` → `DexFile.mCookie`。
- 数组长度必须用 `java.lang.reflect.Array.getLength()`，不要用 `.length`。

## 类名枚举兜底

`enumerate.js` 使用：

```js
Java.cast(dex, DexFileClass).entries()
Collections.list(enumeration)
```

把每个 DexFile 的类名写到 `files/apu/<run>/classes/*.txt`。这不是 DEX 字节，
只用于确认解密成功、类数量或定位包名类。

## 反检测注意事项

- 脚本可选 anti-kill：replace `exit/_exit/abort/quick_exit/kill/tgkill/raise`。
- 只对走 PLT/GOT 的调用有效；对 inline `syscall 231 (exit_group)` 无效。
- 因此 Bangcle/新版 360 不要依赖 anti-kill；一次失败就转 dd。
- 不要重打包 APK；不要在设备上改 APK 签名。

## 失败排查

| 现象 | 处理 |
|---|---|
| 无 `hello` | 检查 frida-server、forward、版本；`frida-ps -H` 探测 |
| 有 `hello` 无 `ready` | Application 未就绪/App 崩溃；换 attach 或 dd |
| 有 `candidate` 无 `saved` | 偏移不匹配或 DEX magic 不成立；检查 Android 版本/架构 |
| `done ok:false` | 进程被反调试杀死；转 dd/freeze |
| pull 失败 | root/权限；尝试 `run-as` 或 `exec-out cat` |
