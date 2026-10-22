from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from pathlib import Path
from typing import Any


def to_jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return to_jsonable(asdict(value))
    if isinstance(value, dict):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    return value


@dataclass
class MapRegion:
    start: int
    end: int
    perms: str
    offset: int = 0
    dev: str = ""
    inode: int = 0
    path: str = ""
    score: int = 0
    score_reasons: list[str] = field(default_factory=list)

    @property
    def size(self) -> int:
        return max(0, self.end - self.start)

    @property
    def readable(self) -> bool:
        return "r" in self.perms

    def to_dict(self) -> dict[str, Any]:
        data = to_jsonable(self)
        data["size"] = self.size
        data["readable"] = self.readable
        return data


@dataclass
class DexHeader:
    magic: str
    version: str
    checksum: int
    signature: str
    file_size: int
    header_size: int
    endian_tag: int
    string_ids_size: int
    string_ids_off: int
    type_ids_size: int
    type_ids_off: int
    class_defs_size: int
    class_defs_off: int
    data_size: int
    data_off: int

    def to_dict(self) -> dict[str, Any]:
        return to_jsonable(self)


@dataclass
class DexCandidate:
    label: str
    source: str
    local_path: str
    device_path: str | None = None
    vaddr: int | None = None
    size: int = 0
    file_size: int = 0
    class_defs_size: int = 0
    dex_version: str = ""
    sha256: str = ""
    complete: bool = False
    truncated: bool = False
    holes: int = 0
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return to_jsonable(self)


@dataclass
class DexRepairReport:
    source_path: str
    output_path: str | None
    status: str
    sha256: str = ""
    size: int = 0
    original_file_size: int = 0
    repaired_file_size: int = 0
    dex_version: str = ""
    class_defs_size: int = 0
    checksum_valid: bool = False
    signature_valid: bool = False
    duplicate_of: str | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return to_jsonable(self)


@dataclass
class MutationRecord:
    mutation_id: str
    kind: str
    target: str
    detail: dict[str, Any]
    apply_command: list[str] | str | None = None
    restore_command: list[str] | str | None = None
    reversible: bool = True
    state: str = "applied"
    timestamp: str = ""
    evidence_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return to_jsonable(self)
