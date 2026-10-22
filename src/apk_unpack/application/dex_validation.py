"""Defensive DEX content assessment shared by the dump/repair/verify chain.

Magic bytes alone are not proof that a DEX is usable: memory dumps can be
truncated, zero-filled, or contain only a shell loader.  This module parses the
header defensively, walks the class table, and reports why a candidate is or is
not complete.  It has no provider dependencies so every layer (providers,
application workflow, backend finalization) can use the same rules.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ..domain.models import DexHeader

DEX_MAGIC = b"dex\n"
DEX_VERSIONS = (b"035\x00", b"037\x00", b"038\x00", b"039\x00", b"040\x00")
CDEX_MAGIC = b"cdex"
HEADER_SIZE = 0x70
ENDIAN_TAG = 0x12345678
MAX_DEX_BYTES = 512 * 1024 * 1024
MAX_CLASSES = 1_000_000
MAX_CLASS_DATA_BYTES = 4 * 1024 * 1024
MIN_HOLE_BYTES = 4096
MAX_HOLE_OFFSETS = 64
MAX_DESCRIPTOR_BYTES = 4096
_IO_CHUNK = 4 * 1024 * 1024
_DEFAULT_MIN_CLASSES = 10

# Known shell/loader class prefixes.  A file is only treated as a shell loader
# when these classes dominate the file (see :func:`_is_shell_like`), so a normal
# app that merely bundles a few SDK classes under one of these packages is not
# rejected.
SHELL_CLASS_PREFIXES = (
    "Lcom/Proxy/",
    "Lcom/Install/",
    "Lcom/stub/",
    "Lcom/qihoo/",
    "Lcom/secneo/",
    "Lcom/tencent/StubShell/",
    "Ls/h/e/l/l/",
)

# A loader-only DEX is always shell-like.  Otherwise loader classes must both
# dominate (>= 50% of named classes) and be numerous (>= 10) before the file is
# vetoed; a handful of vendor SDK classes in an app is normal.
SHELL_DOMINANCE_MIN_CLASSES = 10
SHELL_DOMINANCE_NUMERATOR = 1
SHELL_DOMINANCE_DENOMINATOR = 2

# A single-class DEX is the classic loader/stub shape even when the class is
# named after the target package (the stock fixtures and real packers both use
# this shape).  Two or more coded classes in the expected package are accepted
# as a small but legitimate app instead of being called a stub purely because
# the class count is below ``min_classes``.
MIN_TARGET_APP_CLASSES = 2

_CLASS_DEF_ITEM_SIZE = 32


@dataclass
class DexAssessment:
    """Structured verdict for one DEX file.

    ``complete`` is the only field callers should treat as "usable as-is".
    ``truncated`` means the declared header size exceeds the bytes on disk.
    """

    path: str
    # ``content_complete`` is structural integrity (header/checksums/classes/
    # holes).  ``complete`` additionally requires target package classes when an
    # expected package was supplied.  Multi-dex apps often have runtime DEX files
    # that are structurally complete but contain no app-package classes; those
    # must not make the whole verification look partial.
    complete: bool = False
    content_complete: bool = False
    # A live dump can have a stale checksum/signature while the class table and
    # code are intact; repair recomputes those header fields.  Candidate
    # acceptance uses this field so such DEX files reach repair instead of
    # being rejected before they can be fixed.
    repairable_complete: bool = False
    truncated: bool = False
    declared_size: int = 0
    actual_size: int = 0
    size_ok: bool = False
    checksum_ok: bool = False
    signature_ok: bool = False
    adler_ok: bool = False
    class_defs: int = 0
    classes_with_code: int = 0
    type_ids: int = 0
    string_ids: int = 0
    package_classes: int = 0
    expected_package: str | None = None
    target_packages: list[str] = field(default_factory=list)
    # Useful input for a best-effort decompiler; this never implies complete.
    recoverable: bool = False
    stub_like: bool = False
    # True when the class table is dominated by well-known shell/loader classes
    # or contains loader classes only.  Shell DEX content is never complete,
    # even if it happens to carry a class from the target package.
    shell_like: bool = False
    holes: int = 0
    reasons: list[str] = field(default_factory=list)
    # Additional context (safe to add; keep the shared fields above stable).
    header_ok: bool = False
    magic_ok: bool = False
    endian_ok: bool = False
    class_defs_valid: int = 0
    named_classes: int = 0
    classes_with_class_data: int = 0
    code_items: int = 0
    shell_classes: int = 0
    trailing_bytes: int = 0
    data_range_ok: bool = False
    dex_version: str = ""
    hole_offsets: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_dex_header(data: bytes) -> DexHeader | None:
    """Parse a standard DEX header, rejecting structurally impossible values.

    The header may declare a ``file_size`` larger than ``len(data)``; truncation
    is diagnosed by :func:`assess_dex`, not by refusing to parse the header.
    """

    if len(data) < HEADER_SIZE:
        return None
    if data[:4] != DEX_MAGIC or data[4:8] not in DEX_VERSIONS:
        return None
    try:
        values = struct.unpack_from("<26I", data, 0x08)
    except struct.error:
        return None
    checksum = values[0]
    signature = data[0x0C:0x20].hex()
    file_size = values[6]
    header_size = values[7]
    endian_tag = values[8]
    string_ids_size = values[12]
    string_ids_off = values[13]
    type_ids_size = values[14]
    type_ids_off = values[15]
    class_defs_size = values[22]
    class_defs_off = values[23]
    data_size = values[24]
    data_off = values[25]

    if header_size != HEADER_SIZE or endian_tag != ENDIAN_TAG:
        return None
    if not (HEADER_SIZE <= file_size <= MAX_DEX_BYTES):
        return None
    if class_defs_size > MAX_CLASSES or string_ids_size > MAX_CLASSES or type_ids_size > MAX_CLASSES:
        return None
    try:
        for size, offset, item_size in (
            (string_ids_size, string_ids_off, 4),
            (type_ids_size, type_ids_off, 4),
            (class_defs_size, class_defs_off, _CLASS_DEF_ITEM_SIZE),
        ):
            if size and not (HEADER_SIZE <= offset <= file_size):
                return None
            if size and offset + size * item_size > file_size:
                return None
    except OverflowError:  # pragma: no cover - uint32 arithmetic cannot overflow in Python
        return None
    if data_size and data_off < HEADER_SIZE:
        return None
    return DexHeader(
        magic="dex",
        version=data[4:7].decode("ascii", errors="replace"),
        checksum=checksum,
        signature=signature,
        file_size=file_size,
        header_size=header_size,
        endian_tag=endian_tag,
        string_ids_size=string_ids_size,
        string_ids_off=string_ids_off,
        type_ids_size=type_ids_size,
        type_ids_off=type_ids_off,
        class_defs_size=class_defs_size,
        class_defs_off=class_defs_off,
        data_size=data_size,
        data_off=data_off,
    )


def _read_at(path: Path, offset: int, size: int) -> bytes:
    if size <= 0 or offset < 0:
        return b""
    try:
        with open(path, "rb") as handle:
            handle.seek(offset)
            return handle.read(size)
    except (OSError, ValueError):
        return b""


def _read_uleb128(raw: bytes, offset: int = 0) -> tuple[int, int]:
    value = 0
    shift = 0
    position = offset
    while position < len(raw):
        byte = raw[position]
        position += 1
        value |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            break
        shift += 7
        if shift > 35:
            break
    return value, position


def _decode_mutf8(raw: bytes) -> str:
    """Decode a string_data_item: uleb128 utf16 length followed by MUTF-8 bytes."""

    _, position = _read_uleb128(raw, 0)
    end = raw.find(b"\x00", position)
    payload = raw[position:end] if end >= 0 else raw[position:]
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        # MUTF-8 represents NUL as C0 80 and supplementary chars as CESU-8
        # surrogate pairs, which strict UTF-8 rejects.  Replacement decoding is
        # safe for descriptor/package matching.
        return payload.decode("utf-8", errors="replace")


def _descriptor_name(descriptor: str) -> str:
    if len(descriptor) >= 2 and descriptor.startswith("L") and descriptor.endswith(";"):
        return descriptor[1:-1].replace("/", ".")
    return descriptor


def _matches_package(descriptor: str, package: str | list[str] | None) -> bool:
    if not package:
        return False
    name = _descriptor_name(descriptor)
    if isinstance(package, list):
        return any(name == item or name.startswith(item + ".") for item in package)
    return name == package or name.startswith(package + ".")


def _parse_class_data(blob: bytes) -> tuple[bool, int] | None:
    """Return ``(has_class_data, code_items)`` or None when unparseable."""

    if not blob:
        return None
    position = 0
    sizes: list[int] = []
    for _ in range(4):
        value, position = _read_uleb128(blob, position)
        if position > len(blob):
            return None
        sizes.append(value)
    if any(size > MAX_CLASSES for size in sizes):
        return None
    static_fields, instance_fields, direct_methods, virtual_methods = sizes
    field_count = static_fields + instance_fields
    method_count = direct_methods + virtual_methods
    for _ in range(field_count):
        _, position = _read_uleb128(blob, position)
        _, position = _read_uleb128(blob, position)
        if position > len(blob):
            break
    code_items = 0
    for _ in range(method_count):
        _, position = _read_uleb128(blob, position)
        _, position = _read_uleb128(blob, position)
        code_off, position = _read_uleb128(blob, position)
        if position > len(blob):
            break
        if code_off:
            code_items += 1
    has_data = field_count + method_count > 0
    return has_data, code_items


def _walk_classes(
    path: Path,
    header: DexHeader,
    limit: int,
    expected_package: str | None,
) -> dict[str, int]:
    """Count class defs, classes with code, code items, and package classes."""

    result = {
        "class_defs_valid": 0,
        "named_classes": 0,
        "package_classes": 0,
        "classes_with_code": 0,
        "classes_with_class_data": 0,
        "code_items": 0,
        "shell_classes": 0,
    }
    if not header.class_defs_size or header.class_defs_off >= limit:
        return result
    available = max(0, limit - header.class_defs_off)
    table_size = min(header.class_defs_size * _CLASS_DEF_ITEM_SIZE, available)
    class_table = _read_at(path, header.class_defs_off, table_size)
    if not class_table:
        return result

    type_entries = min(header.type_ids_size, max(0, limit - header.type_ids_off) // 4)
    type_table = _read_at(path, header.type_ids_off, type_entries * 4) if type_entries else b""
    string_entries = min(header.string_ids_size, max(0, limit - header.string_ids_off) // 4)
    string_table = _read_at(path, header.string_ids_off, string_entries * 4) if string_entries else b""

    for index in range(len(class_table) // _CLASS_DEF_ITEM_SIZE):
        entry_off = index * _CLASS_DEF_ITEM_SIZE
        class_idx = struct.unpack_from("<I", class_table, entry_off)[0]
        class_data_off = struct.unpack_from("<I", class_table, entry_off + 24)[0]
        result["class_defs_valid"] += 1
        descriptor = ""
        if class_idx < header.type_ids_size and (class_idx + 1) * 4 <= len(type_table):
            string_idx = struct.unpack_from("<I", type_table, class_idx * 4)[0]
            if string_idx < header.string_ids_size and (string_idx + 1) * 4 <= len(string_table):
                string_off = struct.unpack_from("<I", string_table, string_idx * 4)[0]
                if HEADER_SIZE <= string_off < limit:
                    raw = _read_at(path, string_off, min(MAX_DESCRIPTOR_BYTES, limit - string_off))
                    descriptor = _decode_mutf8(raw) if raw else ""
        if descriptor:
            result["named_classes"] += 1
            if _matches_package(descriptor, expected_package):
                result["package_classes"] += 1
            if descriptor.startswith(SHELL_CLASS_PREFIXES):
                result["shell_classes"] += 1
        if class_data_off and class_data_off < limit:
            blob = _read_at(path, class_data_off, min(MAX_CLASS_DATA_BYTES, limit - class_data_off))
            parsed = _parse_class_data(blob)
            if parsed is not None:
                has_data, code_items = parsed
                if has_data:
                    result["classes_with_class_data"] += 1
                if code_items:
                    result["classes_with_code"] += 1
                result["code_items"] += code_items
    return result


def _adler32_stream(path: Path, start: int = 0x0C) -> int:
    value = 1
    try:
        with open(path, "rb") as handle:
            handle.seek(start)
            while True:
                chunk = handle.read(_IO_CHUNK)
                if not chunk:
                    break
                value = zlib.adler32(chunk, value)
    except OSError:
        return -1
    return value & 0xFFFFFFFF


def _sha1_stream(path: Path, start: int = 0x20) -> str:
    digest = hashlib.sha1()
    try:
        with open(path, "rb") as handle:
            handle.seek(start)
            while True:
                chunk = handle.read(_IO_CHUNK)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def _find_zero_holes(path: Path, start: int, end: int, minimum: int = MIN_HOLE_BYTES) -> tuple[int, list[int]]:
    """Count long all-zero runs inside ``[start, end)``.

    Streams the range and uses ``bytes.find`` so multi-hundred-megabyte dumps do
    not require a full in-memory copy.
    """

    if end <= start:
        return 0, []
    if end - start < minimum:
        return 0, []
    needle = b"\x00" * minimum
    overlap = minimum - 1
    count = 0
    offsets: list[int] = []
    position = start
    carry = b""
    try:
        with open(path, "rb") as handle:
            handle.seek(start)
            remaining = end - start
            while remaining > 0:
                chunk = handle.read(min(_IO_CHUNK, remaining))
                if not chunk:
                    break
                block = carry + chunk
                search_from = 0
                while True:
                    found = block.find(needle, search_from)
                    if found < 0:
                        break
                    absolute = position - len(carry) + found
                    count += 1
                    if len(offsets) < MAX_HOLE_OFFSETS:
                        offsets.append(absolute)
                    search_from = found + minimum
                carry = block[-overlap:] if len(block) > overlap else block
                position += len(chunk)
                remaining -= len(chunk)
    except OSError:
        return count, offsets
    return count, offsets


def _is_shell_like(shell_classes: int, named_classes: int) -> bool:
    """True when loader classes dominate (or are the only classes in) a DEX."""

    if shell_classes <= 0 or named_classes <= 0:
        return False
    if shell_classes >= named_classes:
        # Every named class comes from a known loader package: the file is a
        # loader even if it is small.
        return True
    return (
        shell_classes >= SHELL_DOMINANCE_MIN_CLASSES
        and shell_classes * SHELL_DOMINANCE_DENOMINATOR
        >= named_classes * SHELL_DOMINANCE_NUMERATOR
    )


def assess_dex(
    path: str | Path,
    expected_package: str | None = None,
    min_classes: int = _DEFAULT_MIN_CLASSES,
    allow_truncated: bool = False,
    *,
    target_packages: list[str] | None = None,
) -> DexAssessment:
    """Assess one DEX file defensively.

    ``complete`` is True only for a self-consistent file with code, no large
    zero holes, at least ``min_classes`` class definitions (or a small, clearly
    targeted app), and (when ``expected_package`` is given) at least one class
    in that package.  Shell/loader-dominated content is never complete.

    ``allow_truncated`` is accepted for API symmetry with the repair path.  It
    never makes a truncated file complete; the assessment still reports
    ``truncated=True``, ``complete=False`` and a ``truncated`` reason.
    """

    source = Path(path)
    namespaces = list(dict.fromkeys([p for p in [expected_package, *(target_packages or [])] if p]))
    assessment = DexAssessment(path=str(source), expected_package=expected_package, target_packages=namespaces)
    try:
        assessment.actual_size = source.stat().st_size
    except OSError as exc:
        assessment.reasons.append(f"unreadable:{exc.__class__.__name__}")
        return assessment

    try:
        with open(source, "rb") as handle:
            header_bytes = handle.read(HEADER_SIZE)
    except OSError as exc:
        assessment.reasons.append(f"unreadable:{exc.__class__.__name__}")
        return assessment

    assessment.magic_ok = header_bytes[:4] == DEX_MAGIC
    header = parse_dex_header(header_bytes)
    if header is None:
        assessment.reasons.append("invalid_header")
        return assessment

    assessment.header_ok = True
    assessment.endian_ok = header.endian_tag == ENDIAN_TAG
    assessment.dex_version = header.version
    assessment.declared_size = header.file_size
    assessment.type_ids = header.type_ids_size
    assessment.string_ids = header.string_ids_size
    assessment.class_defs = header.class_defs_size
    assessment.truncated = assessment.actual_size < header.file_size
    assessment.size_ok = assessment.actual_size >= header.file_size
    assessment.trailing_bytes = max(0, assessment.actual_size - header.file_size)
    limit = min(assessment.actual_size, header.file_size)
    assessment.data_range_ok = (
        header.data_size == 0 or header.data_off + header.data_size <= header.file_size
    )

    counts = _walk_classes(source, header, limit, namespaces)
    assessment.class_defs_valid = counts["class_defs_valid"]
    assessment.named_classes = counts["named_classes"]
    assessment.package_classes = counts["package_classes"]
    assessment.classes_with_code = counts["classes_with_code"]
    assessment.classes_with_class_data = counts["classes_with_class_data"]
    assessment.code_items = counts["code_items"]
    assessment.shell_classes = counts["shell_classes"]

    threshold = max(0, int(min_classes))
    assessment.shell_like = _is_shell_like(assessment.shell_classes, assessment.named_classes)
    # Do not call a small app a stub just because it packs fewer than
    # ``min_classes`` classes: when the expected package is known and the file
    # carries its classes, it is a legitimate (tiny) target DEX.  Genuine
    # stub signals (no classes, no code, a single loader-shaped class) remain.
    small_targeted_app = bool(
        namespaces
        and assessment.package_classes >= MIN_TARGET_APP_CLASSES
        and assessment.classes_with_code > 0
    )
    assessment.stub_like = bool(
        assessment.classes_with_code == 0
        or (assessment.class_defs < threshold and not small_targeted_app)
    )

    if header.data_size and header.data_off < limit:
        scan_start = max(HEADER_SIZE, header.data_off)
        scan_end = min(limit, header.data_off + header.data_size)
        assessment.holes, assessment.hole_offsets = _find_zero_holes(source, scan_start, scan_end)

    assessment.adler_ok = _adler32_stream(source) == header.checksum
    assessment.checksum_ok = assessment.adler_ok
    assessment.signature_ok = _sha1_stream(source) == header.signature

    if assessment.truncated:
        assessment.reasons.append("truncated")
    if assessment.trailing_bytes:
        assessment.reasons.append(f"trailing_bytes={assessment.trailing_bytes}")
    if not assessment.data_range_ok:
        assessment.reasons.append("data_range_invalid")
    if not assessment.checksum_ok:
        assessment.reasons.append("checksum_mismatch")
    if not assessment.signature_ok:
        assessment.reasons.append("signature_mismatch")
    if assessment.class_defs == 0:
        assessment.reasons.append("no_class_defs")
    elif assessment.class_defs_valid == 0:
        assessment.reasons.append("no_parseable_class_defs")
    if assessment.classes_with_code == 0:
        assessment.reasons.append("no_classes_with_code")
    if assessment.stub_like:
        assessment.reasons.append("stub_like")
    if assessment.shell_like:
        assessment.reasons.append("shell_loader")
    if assessment.holes:
        assessment.reasons.append(f"zero_holes={assessment.holes}")
    if namespaces and assessment.package_classes == 0:
        assessment.reasons.append("package_not_found")

    assessment.repairable_complete = bool(
        assessment.header_ok
        and assessment.magic_ok
        and assessment.endian_ok
        and not assessment.truncated
        and assessment.size_ok
        and assessment.data_range_ok
        and assessment.class_defs > 0
        and assessment.classes_with_code > 0
        and not assessment.stub_like
        and not assessment.shell_like
        and assessment.holes == 0
    )
    assessment.content_complete = bool(
        assessment.repairable_complete
        and assessment.checksum_ok
        and assessment.signature_ok
        and assessment.adler_ok
    )
    assessment.complete = bool(
        assessment.content_complete
        and (not namespaces or assessment.package_classes > 0)
    )
    assessment.recoverable = bool(
        assessment.header_ok and assessment.data_range_ok
        and not assessment.truncated and assessment.size_ok
        and assessment.named_classes >= MIN_TARGET_APP_CLASSES
        and assessment.classes_with_code >= MIN_TARGET_APP_CLASSES
        and not assessment.stub_like and not assessment.shell_like
        and (not namespaces or assessment.package_classes > 0)
    )
    return assessment


def is_usable_dex(
    path: str | Path,
    expected_package: str | None = None,
    min_classes: int = _DEFAULT_MIN_CLASSES,
) -> bool:
    """True only when :func:`assess_dex` reports the DEX as complete."""

    return assess_dex(path, expected_package, min_classes=min_classes).complete
