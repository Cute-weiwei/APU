from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

RES_XML_TYPE = 0x0003
RES_STRING_POOL_TYPE = 0x0001
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_RESOURCE_MAP_TYPE = 0x0180
UTF8_FLAG = 0x100

TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12


class AxmlError(Exception):
    pass


@dataclass
class AxmlElement:
    name: str
    attrs: dict[str, Any] = field(default_factory=dict)
    children: list["AxmlElement"] = field(default_factory=list)

    def child(self, name: str) -> "AxmlElement | None":
        for item in self.children:
            if item.name == name:
                return item
        return None

    def find_all(self, name: str) -> list["AxmlElement"]:
        found: list[AxmlElement] = []
        for item in self.children:
            if item.name == name:
                found.append(item)
            found.extend(item.find_all(name))
        return found


def _u8(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 1 > len(data):
        raise AxmlError("short read (u8)")
    return data[offset]


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise AxmlError("short read (u16)")
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise AxmlError("short read (u32)")
    return struct.unpack_from("<I", data, offset)[0]


def _i32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise AxmlError("short read (i32)")
    return struct.unpack_from("<i", data, offset)[0]


def _len8(data: bytes, offset: int) -> tuple[int, int]:
    first = _u8(data, offset)
    if first & 0x80:
        second = _u8(data, offset + 1)
        return ((first & 0x7F) << 8) | second, offset + 2
    return first, offset + 1


def _len16(data: bytes, offset: int) -> tuple[int, int]:
    first = _u16(data, offset)
    if first & 0x8000:
        second = _u16(data, offset + 2)
        return ((first & 0x7FFF) << 16) | second, offset + 4
    return first, offset + 2


def _parse_string_pool(data: bytes, chunk_offset: int, chunk_size: int) -> list[str]:
    header_size = _u16(data, chunk_offset + 2)
    string_count = _u32(data, chunk_offset + 8)
    flags = _u32(data, chunk_offset + 16)
    strings_start = _u32(data, chunk_offset + 20)
    if string_count > 1_000_000:
        raise AxmlError("string pool too large")
    offsets_start = chunk_offset + header_size
    strings_base = chunk_offset + strings_start
    strings: list[str] = []
    utf8 = bool(flags & UTF8_FLAG)
    for index in range(string_count):
        offset = _u32(data, offsets_start + index * 4)
        position = strings_base + offset
        if utf8:
            _, position = _len8(data, position)
            byte_length, position = _len8(data, position)
            raw = data[position : position + byte_length]
            strings.append(raw.decode("utf-8", errors="replace"))
        else:
            char_length, position = _len16(data, position)
            raw = data[position : position + char_length * 2]
            strings.append(raw.decode("utf-16-le", errors="replace"))
    return strings


def _typed_value(strings: list[str], data_type: int, data_value: int) -> Any:
    if data_type == TYPE_STRING:
        if 0 <= data_value < len(strings):
            return strings[data_value]
        return None
    if data_type in (TYPE_INT_DEC, TYPE_INT_HEX):
        return data_value if data_value < 0x80000000 else data_value - 0x100000000
    if data_type == TYPE_INT_BOOLEAN:
        return data_value != 0
    if data_type == TYPE_REFERENCE:
        return f"@0x{data_value:08x}"
    if data_type == TYPE_ATTRIBUTE:
        return f"?0x{data_value:08x}"
    if data_type == TYPE_FLOAT:
        return struct.unpack("<f", struct.pack("<I", data_value & 0xFFFFFFFF))[0]
    if data_type == TYPE_NULL:
        return None
    return data_value


def parse_axml(data: bytes) -> list[AxmlElement]:
    if len(data) < 8:
        raise AxmlError("file too short")
    root_type, root_header_size, root_size = struct.unpack_from("<HHI", data, 0)
    if root_type != RES_XML_TYPE or root_header_size < 8:
        raise AxmlError(f"not an Android binary XML (type={root_type:#x})")
    if root_size > len(data):
        root_size = len(data)
    strings: list[str] = []
    stack: list[AxmlElement] = []
    roots: list[AxmlElement] = []
    position = root_header_size
    while position + 8 <= root_size:
        chunk_type, chunk_header_size, chunk_size = struct.unpack_from("<HHI", data, position)
        if chunk_size < 8 or position + chunk_size > len(data):
            break
        if chunk_type == RES_STRING_POOL_TYPE:
            strings = _parse_string_pool(data, position, chunk_size)
        elif chunk_type == RES_XML_START_ELEMENT_TYPE:
            element = _parse_start_element(data, position, strings)
            if stack:
                stack[-1].children.append(element)
            else:
                roots.append(element)
            stack.append(element)
        elif chunk_type == RES_XML_END_ELEMENT_TYPE:
            if stack:
                stack.pop()
        # namespace and resource-map chunks are intentionally ignored: local
        # attribute names are available through the string pool.
        position += chunk_size
    if not roots:
        raise AxmlError("no elements found")
    return roots


def _parse_start_element(data: bytes, chunk_offset: int, strings: list[str]) -> AxmlElement:
    node_header_size = _u16(data, chunk_offset + 2)
    ext_offset = chunk_offset + node_header_size
    name_index = _u32(data, ext_offset + 4)
    attribute_start = _u16(data, ext_offset + 8)
    attribute_size = _u16(data, ext_offset + 10)
    attribute_count = _u16(data, ext_offset + 12)
    if attribute_size < 20:
        attribute_size = 20
    name = strings[name_index] if 0 <= name_index < len(strings) else f"#{name_index}"
    element = AxmlElement(name=name)
    attrs_offset = ext_offset + attribute_start
    for index in range(attribute_count):
        offset = attrs_offset + index * attribute_size
        attr_name_index = _u32(data, offset + 4)
        raw_value_index = _u32(data, offset + 8)
        typed_size = _u16(data, offset + 12)
        data_type = _u8(data, offset + 15)
        data_value = _u32(data, offset + 16)
        attr_name = strings[attr_name_index] if 0 <= attr_name_index < len(strings) else f"#{attr_name_index}"
        if raw_value_index != 0xFFFFFFFF and raw_value_index < len(strings):
            value: Any = strings[raw_value_index]
        else:
            value = _typed_value(strings, data_type, data_value)
        if attr_name:
            element.attrs[attr_name] = value
    return element


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0) if value.lower().startswith("0x") else int(value)
        except ValueError:
            return None
    return None


def extract_manifest(data: bytes) -> dict[str, Any]:
    roots = parse_axml(data)
    manifest = next((item for item in roots if item.name == "manifest"), roots[0])
    result: dict[str, Any] = {
        "package": manifest.attrs.get("package"),
        "version_code": _as_int(manifest.attrs.get("versionCode")),
        "version_name": manifest.attrs.get("versionName"),
        "application_class": None,
        "app_component_factory": None,
        "min_sdk": None,
        "target_sdk": None,
        "launchable_activity": None,
        "activities": [],
        "permissions": [],
        "parser": "axml",
    }
    uses_sdk = manifest.child("uses-sdk")
    if uses_sdk:
        result["min_sdk"] = _as_int(uses_sdk.attrs.get("minSdkVersion"))
        result["target_sdk"] = _as_int(uses_sdk.attrs.get("targetSdkVersion"))
    application = manifest.child("application")
    if application:
        result["application_class"] = application.attrs.get("name")
        result["app_component_factory"] = application.attrs.get("appComponentFactory")
        for activity in application.children:
            if activity.name not in ("activity", "activity-alias"):
                continue
            activity_name = activity.attrs.get("name")
            if not activity_name:
                continue
            result["activities"].append(activity_name)
            if result["launchable_activity"]:
                continue
            actions: set[str] = set()
            categories: set[str] = set()
            for intent_filter in activity.children:
                if intent_filter.name != "intent-filter":
                    continue
                for child in intent_filter.children:
                    if child.name == "action":
                        actions.add(str(child.attrs.get("name")))
                    elif child.name == "category":
                        categories.add(str(child.attrs.get("name")))
            if "android.intent.action.MAIN" in actions and "android.intent.category.LAUNCHER" in categories:
                result["launchable_activity"] = activity_name
        if not result["launchable_activity"] and result["activities"]:
            result["launchable_activity"] = result["activities"][0]
    for permission in manifest.find_all("uses-permission"):
        name = permission.attrs.get("name")
        if name:
            result["permissions"].append(str(name))
    return result
