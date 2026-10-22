# 壳签名与识别

静态检测同时使用四类证据：ZIP 条目、DEX 字符串、Manifest 字段、运行时崩溃栈/日志。
不要在只有单一弱信号时下定论；输出 `layers` 而不是只报一个壳。

## 签名表

### 爱加密 ijiami

| 类型 | 特征 |
|---|---|
| ZIP | `assets/ijiami.dat`、`assets/ijiami.ajm`、`assets/IJMDal.Data`、`assets/ijm_lib/<abi>/libexec.so`、`libexecmain.so`、`assets/libijmDataEncryption_*.so` |
| ZIP | `lib/<abi>/libijm-emulator.so`、`libijmdetect-drisk.so`、`libijiami_bobpay.so` |
| DEX 字符串 | `s.h.e.l.l.S`、`s.h.e.l.l.N`、`s.h.e.l.l.A`、`com.ijm.dataencryption.DETool` |
| Manifest | `appComponentFactory=s.h.e.l.l.A`（这是壳自己的，不要删） |

### 梆梆 Bangcle / SecNeo

| 类型 | 特征 |
|---|---|
| ZIP | `lib/<abi>/libDexHelper.so`、`libDexHelper-x86.so`、`libdexjni.so`、`libprotectClass.so` |
| DEX 字符串 | `com.secneo.apkwrapper.AP`、`com.secneo.apkwrapper.AW` |
| Manifest | `appComponentFactory=com.secneo.apkwrapper.AP` |
| 内层 SDK | `libSdkHelper_sdk.so`、`com.secneo.sdk.Helper`、`com.secneo.sdk.DexInstall` |

> **最高优先级**：只要出现 `libDexHelper*`，一律按 Bangcle 处理，即使同时看到 ijiami
> 组件（常见混合壳）。Frida 对 Bangcle 基本免疫，直接 dd。

### 360 加固（旧版 / 新版变种）

| 类型 | 特征 |
|---|---|
| ZIP | `lib/<abi>/libjiagu.so`、`libjiagu_art.so`、`libjgdtc.so`、`libzxprotect.so`、`assets/.jgapp`、`assets/.jiagu` |
| DEX 字符串 | `com.stub.StubApp`、`QHClassLoader`、`com.qihoo.util` |
| 运行目录 | `.jiagu/`、`tmp.dex`（占位，不是真实 DEX） |
| 双层 | 外层 360 + 内层 `libSdkHelper_sdk.so` / `com.secneo.sdk.*` |

### 腾讯 MTP / 几维

| 类型 | 特征 |
|---|---|
| ZIP | `lib/<abi>/libshell-super.<pkg>.so`、`libshella-<ver>.so`、`libshellx-super.*.so`、`assets/0OO00l111l1l`、`assets/o0oooOO0ooOo.dat` |
| 相关 | `libtup.so`、`libnqshield.so`、`libsgmain.so` |
| 运行时 | `files/prodexdir/*.dex` 落盘；`WrapperProxyApplication`、`CustomerClassLoader` |

## 加固判据

- 顶层 `classes*.dex` 的 `class_defs_size@0x60 <= 10` → 加固 stub。
- `entry_size > data_off + data_size` 的尾部是加密数据，尾部越大越可疑。
- 所有顶层 DEX 的 class_defs 总和 ≤ 10 → packed。
- 只有壳签名、没有可解析 DEX → packed=true（可能 split APK）。

## 优先级

```
libDexHelper 出现 → Bangcle
否则 360 > Tencent > ijiami > SecNeo
360 + SecNeo → primary=360, layers=[360, SecNeo]
Uni-app wgt 独立于壳，优先静态提取
```

检测结果必须保留 `precedence_notes`，例如：

- “libDexHelper present: treat as Bangcle regardless of other shell indicators.”
- “360 outer + SecNeo inner: rename the inner SecNeo library before attaching Frida.”

## 误判护栏

- 看到 `ijiami_bobpay` 不能只按纯 ijiami；先找 `libDexHelper`。
- 内层 SecNeo 可能静态不显眼，只能从首次启动崩溃栈/`logcat` 发现。
- 包名反转（`com.stub.StubApp` → `elpmaxe.elpmas.moc.StubApp`，匿名示例）也是 360 信号。
- 不要仅凭文件大小判断；MTP 的 `classes2/3.dex` 可能只有 2.4KB 占位。
