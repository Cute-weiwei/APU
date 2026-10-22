from __future__ import annotations

import hashlib
import struct
import zlib
import zipfile
from pathlib import Path
from typing import Any


def _uleb128(value: int) -> bytes:
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            encoded.append(byte | 0x80)
        else:
            encoded.append(byte)
            return bytes(encoded)


def resign_dex(data: bytes) -> bytes:
    """Recompute the SHA-1 signature and Adler32 checksum of a DEX blob."""

    mutated = bytearray(data)
    if len(mutated) < 0x70:
        return bytes(mutated)
    mutated[0x0C:0x20] = hashlib.sha1(bytes(mutated[0x20:])).digest()
    checksum = zlib.adler32(bytes(mutated[0x0C:])) & 0xFFFFFFFF
    mutated[0x08:0x0C] = struct.pack("<I", checksum)
    return bytes(mutated)


def _build_dex_blob(
    descriptors: list[bytes],
    code_classes: set[int],
    *,
    padding: int = 0,
    corrupt: bool = False,
) -> bytes:
    """Build a structurally valid DEX with class_data/code items.

    ``padding`` bytes of non-zero filler are inserted in the data region so
    tests can carve a deliberate zero hole without changing the class layout.
    """

    count = len(descriptors)
    string_ids_off = 0x70
    type_ids_off = string_ids_off + 4 * count
    class_defs_off = type_ids_off + 4 * count
    data_off = class_defs_off + 32 * count

    data = bytearray()
    class_data_offsets: list[int] = []
    # 16-byte code_item header + one return-void instruction (18 bytes).
    code_item = struct.pack("<4HII", 0, 0, 0, 0, 0, 1) + struct.pack("<H", 0x000E)
    for index in range(count):
        if index not in code_classes:
            class_data_offsets.append(0)
            continue
        while len(data) % 4:
            data.append(0)
        code_off = data_off + len(data)
        data.extend(code_item)
        class_data = (
            _uleb128(0)  # static_fields_size
            + _uleb128(0)  # instance_fields_size
            + _uleb128(1)  # direct_methods_size
            + _uleb128(0)  # virtual_methods_size
            + _uleb128(0)  # method_idx_diff
            + _uleb128(1)  # access_flags
            + _uleb128(code_off)
        )
        class_data_offsets.append(data_off + len(data))
        data.extend(class_data)
    if padding:
        data.extend(b"\xA5" * padding)

    string_offsets: list[int] = []
    for descriptor in descriptors:
        string_offsets.append(data_off + len(data))
        data.extend(_uleb128(len(descriptor)))
        data.extend(descriptor)
        data.append(0)

    string_ids = b"".join(struct.pack("<I", offset) for offset in string_offsets)
    type_ids = b"".join(struct.pack("<I", index) for index in range(count))
    class_defs = bytearray()
    for index in range(count):
        class_defs += struct.pack(
            "<8I",
            index,  # class_idx
            1,  # access_flags
            0xFFFFFFFF,  # superclass_idx
            0,  # interfaces_off
            0xFFFFFFFF,  # source_file_idx
            0,  # annotations_off
            class_data_offsets[index],
            0,  # static_values_off
        )

    header = bytearray(0x70)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 0x20, data_off + len(data))
    struct.pack_into("<I", header, 0x24, 0x70)
    struct.pack_into("<I", header, 0x28, 0x12345678)
    struct.pack_into("<I", header, 0x38, count)
    struct.pack_into("<I", header, 0x3C, string_ids_off)
    struct.pack_into("<I", header, 0x40, count)
    struct.pack_into("<I", header, 0x44, type_ids_off)
    struct.pack_into("<I", header, 0x60, count)
    struct.pack_into("<I", header, 0x64, class_defs_off)
    struct.pack_into("<I", header, 0x68, len(data))
    struct.pack_into("<I", header, 0x6C, data_off)

    blob = resign_dex(
        bytes(header) + string_ids + type_ids + bytes(class_defs) + bytes(data)
    )
    if corrupt:
        mutated = bytearray(blob)
        mutated[0x30] ^= 0xFF
        blob = bytes(mutated)
    return blob


def build_dex(
    descriptor: bytes = b"Lcom/example/Foo;",
    *,
    class_defs_size: int = 1,
    corrupt: bool = False,
    classes_with_code: int | None = None,
    padding: int = 0,
) -> bytes:
    """Build a minimal DEX; defaults to a one-class stub (shell-loader shape)."""

    count = max(0, class_defs_size)
    descriptors = [descriptor]
    for index in range(1, count):
        descriptors.append(b"Lcom/example/Class%02d;" % index)
    descriptors = descriptors[:count]
    code_count = count if classes_with_code is None else max(0, min(count, classes_with_code))
    return _build_dex_blob(descriptors, set(range(code_count)), padding=padding, corrupt=corrupt)


def build_valid_dex(
    package: str = "com.example",
    *,
    classes: int = 12,
    classes_with_code: int | None = None,
    padding: int = 0,
    corrupt: bool = False,
) -> bytes:
    """Build a DEX that passes the content assessment (>= 10 coded classes)."""

    prefix = package.replace(".", "/")
    descriptors = [f"L{prefix}/Class{index:02d};".encode() for index in range(max(0, classes))]
    code_count = len(descriptors) if classes_with_code is None else max(0, min(len(descriptors), classes_with_code))
    return _build_dex_blob(descriptors, set(range(code_count)), padding=padding, corrupt=corrupt)


def build_apk(path: Path, entries: dict[str, bytes], manifest: bytes | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        if manifest is not None:
            archive.writestr("AndroidManifest.xml", manifest)
        for name, data in entries.items():
            archive.writestr(name, data)
    return path


def shell_apk(path: Path, shell: str, *, dex: bytes | None = None, manifest: bytes | None = None) -> Path:
    entries: dict[str, bytes] = {"classes.dex": dex or build_dex()}
    if shell == "ijiami":
        entries["assets/ijiami.dat"] = b"ijiami"
        entries["assets/ijiami.ajm"] = b"ajm"
        entries["assets/ijm_lib/x86_64/libexec.so"] = b"so"
    elif shell == "bangcle":
        entries["lib/x86_64/libDexHelper.so"] = b"so"
        entries["lib/x86_64/libdexjni.so"] = b"so"
    elif shell == "bangcle_ijiami":
        entries["lib/x86_64/libDexHelper.so"] = b"so"
        entries["assets/ijiami.dat"] = b"ijiami"
    elif shell == "360":
        entries["lib/x86_64/libjiagu.so"] = b"so"
        entries["assets/.jgapp"] = b"jgapp"
    elif shell == "360_secneo":
        entries["lib/arm64-v8a/libjiagu.so"] = b"so"
        entries["lib/arm64-v8a/libSdkHelper_sdk.so"] = b"so"
    elif shell == "tencent":
        entries["lib/x86_64/libshell-super.com.example.so"] = b"so"
        entries["assets/0OO00l111l1l"] = b"tencent"
    elif shell == "unknown":
        pass
    return build_apk(path, entries, manifest=manifest)


# ---------------------------------------------------------------------------
# Minimal Android binary XML builder (enough for manifest extraction tests)
# ---------------------------------------------------------------------------


class _StringPool:
    def __init__(self) -> None:
        self.strings: list[str] = []
        self.index: dict[str, int] = {}

    def add(self, value: str) -> int:
        if value not in self.index:
            self.index[value] = len(self.strings)
            self.strings.append(value)
        return self.index[value]

    def encode(self) -> bytes:
        data = bytearray()
        offsets: list[int] = []
        for value in self.strings:
            offsets.append(len(data))
            encoded = value.encode("utf-8")
            data.append(len(value) & 0x7F)
            data.append(len(encoded) & 0x7F)
            data.extend(encoded)
            data.append(0)
        header_size = 28
        strings_start = header_size + 4 * len(self.strings)
        total = strings_start + len(data)
        header = struct.pack("<HHI", 0x0001, header_size, total)
        header += struct.pack("<IIIII", len(self.strings), 0, 0x100, strings_start, 0)
        table = b"".join(struct.pack("<I", offset) for offset in offsets)
        return header + table + bytes(data)


def _collect(element: dict[str, Any], pool: _StringPool) -> None:
    pool.add(element["name"])
    for name, value in element.get("attrs", {}).items():
        pool.add(name)
        if isinstance(value, str):
            pool.add(value)
    for child in element.get("children", []):
        _collect(child, pool)


def _serialize(element: dict[str, Any], pool: _StringPool) -> bytes:
    name_index = pool.index[element["name"]]
    attrs = element.get("attrs", {})
    chunks = bytearray()
    size = 16 + 20 + 20 * len(attrs)
    chunks += struct.pack("<HHI", 0x0102, 16, size)
    chunks += struct.pack("<II", 1, 0xFFFFFFFF)
    chunks += struct.pack(
        "<IIHHHHHH",
        0xFFFFFFFF,
        name_index,
        20,
        20,
        len(attrs),
        0,
        0,
        0,
    )
    for attr_name, value in attrs.items():
        attr_index = pool.index[attr_name]
        if isinstance(value, bool):
            raw = 0xFFFFFFFF
            data_type = 0x12
            data = 1 if value else 0
        elif isinstance(value, int):
            raw = 0xFFFFFFFF
            data_type = 0x10
            data = value
        else:
            value_index = pool.index[str(value)]
            raw = value_index
            data_type = 0x03
            data = value_index
        chunks += struct.pack("<III", 0xFFFFFFFF, attr_index, raw)
        chunks += struct.pack("<HBBI", 8, 0, data_type, data)
    for child in element.get("children", []):
        chunks += _serialize(child, pool)
    chunks += struct.pack("<HHI", 0x0103, 16, 24)
    chunks += struct.pack("<II", 1, 0xFFFFFFFF)
    chunks += struct.pack("<II", 0xFFFFFFFF, name_index)
    return bytes(chunks)


def build_axml(root: dict[str, Any]) -> bytes:
    pool = _StringPool()
    _collect(root, pool)
    pool_bytes = pool.encode()
    body = pool_bytes + _serialize(root, pool)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


def build_manifest(
    package: str = "com.example",
    *,
    activity: str = "com.example.Main",
    app_class: str | None = None,
    component_factory: str | None = None,
    version_code: int = 1,
    version_name: str = "1.0",
) -> bytes:
    application: dict[str, Any] = {"name": "application", "attrs": {}, "children": []}
    if app_class:
        application["attrs"]["name"] = app_class
    if component_factory:
        application["attrs"]["appComponentFactory"] = component_factory
    application["children"].append(
        {
            "name": "activity",
            "attrs": {"name": activity},
            "children": [
                {
                    "name": "intent-filter",
                    "attrs": {},
                    "children": [
                        {"name": "action", "attrs": {"name": "android.intent.action.MAIN"}, "children": []},
                        {
                            "name": "category",
                            "attrs": {"name": "android.intent.category.LAUNCHER"},
                            "children": [],
                        },
                    ],
                }
            ],
        }
    )
    root = {
        "name": "manifest",
        "attrs": {
            "package": package,
            "versionCode": version_code,
            "versionName": version_name,
        },
        "children": [
            {"name": "uses-sdk", "attrs": {"minSdkVersion": 21, "targetSdkVersion": 33}, "children": []},
            application,
        ],
    }
    return build_axml(root)


def memory_dump_with_dex(prefix_size: int = 0, dex_bytes: bytes | None = None) -> bytes:
    # Use a content-complete DEX so memory-scan tests exercise the success path.
    dex_bytes = dex_bytes or build_valid_dex()
    return b"\x00" * prefix_size + dex_bytes + b"\x00" * 256


def maps_fixture() -> str:
    return "\n".join(
        [
            "12c00000-12d00000 rw-p 00000000 00:00 0 [anon:dalvik-main space]",
            "7f0000000000-7f0001000000 rw-p 00000000 00:00 0 [anon:libc_malloc]",
            "7f0002000000-7f0002100000 rw-p 00000000 00:00 0 /dev/ashmem/dalvik-DEX data (deleted)",
            "7f0003000000-7f0003001000 r--p 00000000 08:01 123 /system/lib64/libc.so",
            "7ff000000000-7ff000002000 rw-p 00000000 00:00 0 [stack]",
        ]
    )
