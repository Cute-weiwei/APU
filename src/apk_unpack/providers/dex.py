from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import struct
import zlib
from pathlib import Path
from typing import Any, Iterable

from ..application.dex_validation import (
    CDEX_MAGIC,
    DEX_MAGIC,
    DEX_VERSIONS,
    ENDIAN_TAG,
    HEADER_SIZE,
    MAX_CLASSES,
    MAX_DEX_BYTES,
    DexAssessment,
    assess_dex,
    is_usable_dex,
    parse_dex_header,
)
from ..domain.errors import fail
from ..domain.jsonutil import sha256_file
from ..domain.models import DexHeader

__all__ = [
    "CDEX_MAGIC",
    "DEX_MAGIC",
    "DEX_VERSIONS",
    "ENDIAN_TAG",
    "HEADER_SIZE",
    "MAX_CLASSES",
    "MAX_DEX_BYTES",
    "DexAssessment",
    "assess_dex",
    "is_usable_dex",
    "dex_summary_for_apk_entry",
    "parse_dex_header",
    "read_header",
    "repair_dex",
    "repair_dex_set",
    "scan_file_for_dex",
    "verify_dex",
]


def read_header(path: str | Path) -> DexHeader | None:
    try:
        with open(path, "rb") as handle:
            return parse_dex_header(handle.read(HEADER_SIZE))
    except OSError:
        return None


def _safe_label(label: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", label).strip("._")
    return cleaned or "candidate"


def _read_at(path: Path, offset: int, size: int) -> bytes:
    with open(path, "rb") as handle:
        handle.seek(offset)
        return handle.read(size)


def _assessment_notes(assessment: DexAssessment) -> list[str]:
    notes: list[str] = []
    if assessment.truncated:
        notes.append(f"truncated: header file_size={assessment.declared_size} actual={assessment.actual_size}")
    if assessment.trailing_bytes:
        notes.append(f"{assessment.trailing_bytes} trailing bytes past declared file_size")
    if not assessment.checksum_ok:
        notes.append("Adler32 checksum does not match")
    if not assessment.signature_ok:
        notes.append("SHA-1 signature does not match")
    if assessment.stub_like:
        notes.append(
            f"stub-like content: class_defs={assessment.class_defs} classes_with_code={assessment.classes_with_code}"
        )
    if assessment.shell_like:
        notes.append(
            f"shell/loader content dominates: shell_classes={assessment.shell_classes} "
            f"named_classes={assessment.named_classes}"
        )
    if assessment.class_defs and assessment.class_defs_valid == 0:
        notes.append("class_defs_size > 0 but no valid class descriptors were read")
    if assessment.holes:
        notes.append(f"{assessment.holes} large zero block(s) inside the data region")
    if assessment.expected_package and assessment.package_classes == 0:
        notes.append(f"no classes in package {assessment.expected_package}")
    return notes


def scan_file_for_dex(
    path: str | Path,
    out_dir: str | Path,
    *,
    label: str = "region",
    base_vaddr: int | None = None,
    chunk_size: int = 4 * 1024 * 1024,
    max_candidates: int = 128,
) -> list[dict[str, Any]]:
    """Find DEX payloads inside a memory dump and extract them by header file_size."""

    source = Path(path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        file_size = source.stat().st_size
    except OSError as exc:
        raise fail("invalid_input", f"cannot read dump: {exc}")

    offsets: list[int] = []
    overlap = 8
    position = 0
    with open(source, "rb") as handle:
        carry = b""
        while position < file_size:
            handle.seek(position)
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            data = carry + chunk
            base = position - len(carry)
            search = 0
            while True:
                found = data.find(DEX_MAGIC, search)
                if found < 0:
                    break
                absolute = base + found
                if absolute not in offsets:
                    offsets.append(absolute)
                search = found + 4
            carry = data[-(overlap - 1) :]
            position += len(chunk)

    candidates: list[dict[str, Any]] = []
    seen_hashes: set[str] = set()
    for absolute in offsets[:max_candidates]:
        header_bytes = _read_at(source, absolute, HEADER_SIZE)
        header = parse_dex_header(header_bytes)
        if header is None:
            continue
        available = max(0, file_size - absolute)
        take = min(header.file_size, available)
        if take < HEADER_SIZE:
            continue
        payload = _read_at(source, absolute, take)
        digest = hashlib.sha256(payload).hexdigest()
        if digest in seen_hashes:
            continue
        seen_hashes.add(digest)
        # Magic + size are not enough: the extracted payload must pass the same
        # content assessment used by repair/verify before it can be complete.
        scratch = out_dir / f".assess_{digest[:16]}.dex"
        scratch.write_bytes(payload)
        assessment = assess_dex(scratch, min_classes=10)
        if assessment.truncated:
            suffix = "_truncated"
        elif not assessment.complete:
            suffix = "_incomplete"
        else:
            suffix = ""
        filename = f"raw_{_safe_label(label)}_{len(candidates):02d}_{take}{suffix}.dex"
        destination = out_dir / filename
        os.replace(scratch, destination)
        assessment_payload = assessment.to_dict()
        assessment_payload["path"] = str(destination)
        candidates.append(
            {
                "label": f"{_safe_label(label)}_{len(candidates):02d}",
                "source": "memory-scan",
                "local_path": str(destination),
                "device_path": None,
                "vaddr": (base_vaddr + absolute) if base_vaddr is not None else None,
                "size": take,
                "file_size": header.file_size,
                "class_defs_size": header.class_defs_size,
                "classes_with_code": assessment.classes_with_code,
                "package_classes": assessment.package_classes,
                "dex_version": header.version,
                "sha256": digest,
                "complete": assessment.complete,
                "truncated": assessment.truncated,
                "holes": assessment.holes,
                "reasons": list(assessment.reasons),
                "assessment": assessment_payload,
                "notes": _assessment_notes(assessment),
            }
        )
    return candidates


def _adler32_stream(path: Path, start: int = 0x0C) -> int:
    value = 1
    with open(path, "rb") as handle:
        handle.seek(start)
        while True:
            chunk = handle.read(4 * 1024 * 1024)
            if not chunk:
                break
            value = zlib.adler32(chunk, value)
    return value & 0xFFFFFFFF


def _sha1_stream(path: Path, start: int = 0x20) -> str:
    digest = hashlib.sha1()
    with open(path, "rb") as handle:
        handle.seek(start)
        while True:
            chunk = handle.read(4 * 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def verify_dex(
    path: str | Path,
    package: str | None = None,
    *,
    min_classes: int = 10,
    allow_truncated: bool = False,
    target_packages: list[str] | None = None,
) -> dict[str, Any]:
    """Verify one DEX.

    ``status == "complete"`` and ``complete`` now require the shared DEX
    assessment: consistent size/checksum/signature, parseable classes with
    code, no large zero holes, and package classes when a package is supplied.
    """

    source = Path(path)
    assessment = assess_dex(source, package, min_classes=min_classes, allow_truncated=allow_truncated, target_packages=target_packages)
    header = read_header(source) if assessment.header_ok else None
    if not assessment.header_ok:
        readable = bool(assessment.actual_size)
        return {
            "path": str(source),
            "size": assessment.actual_size,
            "sha256": _safe_sha256(source),
            "status": "invalid",
            "complete": False,
            "content_complete": False,
            "repairable_complete": False,
            "stub_like": assessment.stub_like,
            "shell_like": assessment.shell_like,
            "shell_classes": assessment.shell_classes,
            "checks": {
                "readable": readable,
                "magic": assessment.magic_ok,
                "header": False,
            },
            "total_classes": 0,
            "package_classes": 0,
            "notes": _assessment_notes(assessment),
            "reasons": list(assessment.reasons),
            "assessment": assessment.to_dict(),
        }

    checks: dict[str, Any] = {
        "magic": assessment.magic_ok,
        "header": assessment.header_ok,
        "header_size": header.header_size == HEADER_SIZE if header else False,
        "endian": assessment.endian_ok,
        "file_size": header is not None and header.file_size == assessment.actual_size,
        "checksum": assessment.checksum_ok,
        "signature": assessment.signature_ok,
        "class_table": assessment.class_defs == 0 or assessment.class_defs_valid > 0,
        "holes": assessment.holes == 0,
        "has_code": assessment.classes_with_code > 0,
        "not_shell_loader": not assessment.shell_like,
    }
    notes = _assessment_notes(assessment)
    if assessment.complete:
        status = "complete"
    elif assessment.truncated:
        status = "truncated"
    else:
        status = "partial"
    return {
        "path": str(source),
        "size": assessment.actual_size,
        "sha256": _safe_sha256(source),
        "dex_version": assessment.dex_version,
        "file_size": assessment.declared_size,
        "class_defs_size": assessment.class_defs,
        "total_classes": assessment.class_defs_valid,
        "package_classes": assessment.package_classes,
        "classes_with_code": assessment.classes_with_code,
        "code_items": assessment.code_items,
        "holes": assessment.holes,
        "checks": checks,
        "status": status,
        "complete": assessment.complete,
        "content_complete": assessment.content_complete,
        "repairable_complete": assessment.repairable_complete,
        "stub_like": assessment.stub_like,
        "shell_like": assessment.shell_like,
        "shell_classes": assessment.shell_classes,
        "reasons": list(assessment.reasons),
        "notes": notes,
        "assessment": assessment.to_dict(),
    }


def _safe_sha256(path: Path) -> str:
    try:
        return sha256_file(path)
    except OSError:
        return ""


def repair_dex(
    src: str | Path,
    dst: str | Path,
    *,
    allow_truncated: bool = False,
    expected_package: str | None = None,
    min_classes: int = 10,
    target_packages: list[str] | None = None,
) -> dict[str, Any]:
    source = Path(src)
    destination = Path(dst)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        actual_size = source.stat().st_size
    except OSError as exc:
        return {
            "status": "invalid",
            "complete": False,
            "truncated": False,
            "notes": [str(exc)],
            "reasons": ["unreadable"],
            "source_path": str(source),
            "output_path": None,
            "size": 0,
            "assessment": None,
        }
    header = read_header(source)
    if header is None:
        prefix = b""
        try:
            prefix = _read_at(source, 0, 8)
        except OSError:
            pass
        truncated = prefix[:4] == DEX_MAGIC
        reasons = ["truncated_before_header"] if truncated else ["invalid_header"]
        return {
            "status": "truncated" if truncated else "invalid",
            "complete": False,
            "truncated": truncated,
            "notes": ["not a standard DEX (cdex or corrupt/partial header)"],
            "reasons": reasons,
            "source_path": str(source),
            "output_path": None,
            "size": actual_size,
            "assessment": None,
        }
    original_truncated = header.file_size > actual_size
    if original_truncated and not allow_truncated:
        assessment = assess_dex(source, expected_package, min_classes=min_classes, target_packages=target_packages).to_dict()
        return {
            "status": "truncated",
            "complete": False,
            "truncated": True,
            "notes": [f"header file_size={header.file_size} exceeds available={actual_size}"],
            "reasons": ["truncated"],
            "source_path": str(source),
            "output_path": None,
            "size": actual_size,
            "assessment": assessment,
        }
    if original_truncated or header.file_size < HEADER_SIZE:
        target_length = actual_size
    else:
        target_length = header.file_size

    temp = destination.with_name(destination.name + ".part")
    header_bytes = bytearray(_read_at(source, 0, HEADER_SIZE))
    struct.pack_into("<I", header_bytes, 0x20, target_length)
    header_bytes[0x08:0x20] = b"\x00" * 24

    sha1 = hashlib.sha1()
    sha1.update(header_bytes[0x20:HEADER_SIZE])
    with open(source, "rb") as reader, open(temp, "wb") as writer:
        writer.write(header_bytes)
        reader.seek(HEADER_SIZE)
        remaining = target_length - HEADER_SIZE
        while remaining > 0:
            chunk = reader.read(min(4 * 1024 * 1024, remaining))
            if not chunk:
                break
            writer.write(chunk)
            sha1.update(chunk)
            remaining -= len(chunk)
        signature = sha1.digest()
        writer.seek(0x0C)
        writer.write(signature)
        writer.flush()
        os.fsync(writer.fileno())
    checksum = _adler32_stream(temp, start=0x0C)
    with open(temp, "r+b") as writer:
        writer.seek(0x08)
        writer.write(struct.pack("<I", checksum))
        writer.flush()
        os.fsync(writer.fileno())
    os.replace(temp, destination)

    verification = verify_dex(destination, expected_package, min_classes=min_classes, target_packages=target_packages)
    assessment = dict(verification.get("assessment") or {})
    reasons = list(assessment.get("reasons") or [])
    if original_truncated:
        # The header now matches the bytes on disk, but the original dump was
        # short: report it as truncated and never as complete.
        reasons = ["truncated"] + [reason for reason in reasons if reason != "truncated"]
        assessment["truncated"] = True
        assessment["complete"] = False
    assessment["reasons"] = reasons
    complete = bool(verification.get("complete")) and not original_truncated
    if complete:
        status = "complete"
    elif original_truncated:
        status = "truncated"
    elif verification.get("status") == "invalid":
        status = "invalid"
    else:
        status = "partial"
    return {
        "status": status,
        "complete": complete,
        "truncated": original_truncated,
        "source_path": str(source),
        "output_path": str(destination),
        "size": verification["size"],
        "sha256": verification["sha256"],
        "original_file_size": header.file_size,
        "repaired_file_size": target_length,
        "dex_version": header.version,
        "class_defs_size": header.class_defs_size,
        "checksum_valid": verification["checks"].get("checksum", False),
        "signature_valid": verification["checks"].get("signature", False),
        "notes": verification.get("notes", []),
        "reasons": reasons,
        "stub_like": bool(assessment.get("stub_like")),
        "shell_like": bool(assessment.get("shell_like")),
        "assessment": assessment,
    }


def _runtime_variant_key(path: Path) -> tuple[int, int, str, str] | None:
    """Identify equivalent class layouts without hashing repaired checksums.

    Require every class descriptor as well as the class table and prefix;
    matching sizes or a shared namespace alone must never discard a DEX.
    Raw snapshots remain available even when a near variant is not retained.
    """
    header = read_header(path)
    if header is None:
        return None
    blob = path.read_bytes()
    limit = min(len(blob), header.file_size)
    if (header.class_defs_off + header.class_defs_size * 32 > limit
            or header.type_ids_off + header.type_ids_size * 4 > limit
            or header.string_ids_off + header.string_ids_size * 4 > limit):
        return None
    identity = hashlib.sha256(blob[header.class_defs_off:
                                   header.class_defs_off + header.class_defs_size * 32])
    for index in range(header.class_defs_size):
        type_index = struct.unpack_from('<I', blob, header.class_defs_off + index * 32)[0]
        if type_index >= header.type_ids_size:
            return None
        string_index = struct.unpack_from('<I', blob, header.type_ids_off + type_index * 4)[0]
        if string_index >= header.string_ids_size:
            return None
        offset = struct.unpack_from('<I', blob, header.string_ids_off + string_index * 4)[0]
        for _ in range(5):
            if offset >= limit:
                return None
            value = blob[offset]
            offset += 1
            if value < 128:
                break
        else:
            return None
        end = blob.find(b'\0', offset, min(limit, offset + 4096))
        if end < 0:
            return None
        descriptor = blob[offset:end]
        if not descriptor.startswith(b'L') or not descriptor.endswith(b';'):
            return None
        identity.update(struct.pack('<I', len(descriptor)))
        identity.update(descriptor)
    prefix = bytearray(blob[:4096])
    prefix[8:32] = b'\0' * 24  # checksum/signature change with missing tail bytes
    return (header.file_size, header.class_defs_size,
            hashlib.sha256(prefix).hexdigest(), identity.hexdigest())


def _snapshot_quality(item: dict[str, Any]) -> tuple[int, int, int, int]:
    a = item.get('assessment') or {}
    return (int(bool(a.get('content_complete'))), int(a.get('classes_with_code') or 0),
            -int(a.get('holes') or 0), int(a.get('code_items') or 0))


def repair_dex_set(
    input_paths: Iterable[str | Path],
    output_dir: str | Path,
    *,
    allow_truncated: bool = False,
    include_stub: bool = False,
    package: str | None = None,
    min_classes: int = 10,
    target_packages: list[str] | None = None,
    runtime_variants: bool = False,
) -> dict[str, Any]:
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    previous_owned: dict[Path, str] = {}
    try:
        previous = json.loads((out_dir / 'manifest.json').read_text(encoding='utf-8'))
        for item in previous.get('files', []):
            path = Path(item.get('path') or '').resolve()
            if (path.parent == out_dir.resolve()
                    and re.fullmatch(r'classes(?:\d+)?\.dex', path.name)
                    and item.get('sha256')):
                previous_owned[path] = item['sha256']
    except (OSError, ValueError, TypeError):
        pass
    sources = [Path(item) for item in input_paths]
    skipped: list[dict[str, Any]] = []
    repaired: list[dict[str, Any]] = []
    for index, source in enumerate(sorted(sources, key=lambda item: str(item))):
        temp_out = out_dir / f"_tmp_{index:03d}.dex"
        report = repair_dex(
            source,
            temp_out,
            allow_truncated=allow_truncated,
            expected_package=package,
            min_classes=min_classes,
            target_packages=target_packages,
        )
        if not report.get("output_path"):
            skipped.append({"path": str(source), "status": report.get("status"), "notes": report.get("notes", [])})
            try:
                temp_out.unlink(missing_ok=True)
            except OSError:
                pass
            continue
        assessment = report.get("assessment") or {}
        repaired.append(
            {
                **report,
                "stub": bool(assessment.get("stub_like")),
                "shell_like": bool(assessment.get("shell_like")),
                "complete": bool(report.get("complete")),
                "truncated": bool(report.get("truncated")),
                "reasons": list(report.get("reasons") or []),
            }
        )

    # ``include_stub`` controls retention only: True keeps every repaired file
    # (including stubs and shell loaders) for inspection, False drops only
    # genuine stub/shell files.  Legitimate runtime DEX files are never dropped.
    candidates: list[dict[str, Any]] = []
    for item in repaired:
        if not include_stub and (item.get("stub") or item.get("shell_like")):
            reason = "shell_loader" if item.get("shell_like") else "stub_like"
            notes = list(item.get("notes") or [])
            if reason not in notes:
                notes.append(reason)
            skipped.append(
                {
                    "path": item.get("source_path"),
                    "status": item.get("status"),
                    "notes": notes,
                    "reason": reason,
                }
            )
            continue
        candidates.append(item)

    exact_seen: dict[str, dict[str, Any]] = {}
    near_seen: dict[tuple[int, int, str, str], dict[str, Any]] = {}
    retained: list[dict[str, Any]] = []
    duplicates: list[dict[str, Any]] = []
    # Prefer the snapshot with more readable code and fewer holes. Stable path
    # ordering breaks ties; never select a variant just because it sorted first.
    for item in sorted(candidates, key=_snapshot_quality, reverse=True):
        digest = item["sha256"]
        if digest in exact_seen:
            duplicates.append({"path": item["output_path"], "duplicate_of": exact_seen[digest]["output_path"], "kind": "exact"})
            continue
        if runtime_variants:
            near_key = _runtime_variant_key(Path(item["output_path"]))
        else:
            with open(item['output_path'], 'rb') as handle:
                prefix_sha = hashlib.sha256(handle.read(4096)).hexdigest()
            near_key = (int(item.get('size', 0)), int(item.get('class_defs_size', 0)), prefix_sha, '')
        if near_key is not None and near_key in near_seen:
            duplicates.append(
                {"path": item["output_path"], "source_path": item["source_path"],
                 "duplicate_of": near_seen[near_key]["source_path"],
                 "kind": "near_runtime_variant" if runtime_variants else "near",
                 "selected_quality": _snapshot_quality(near_seen[near_key]),
                 "discarded_quality": _snapshot_quality(item)}
            )
            continue
        exact_seen[digest] = item
        if near_key is not None:
            near_seen[near_key] = item
        retained.append(item)

    retained.sort(key=lambda item: (-int(item.get("size", 0)), -int(item.get("class_defs_size", 0)), item["sha256"]))
    files: list[dict[str, Any]] = []
    manifest: list[dict[str, Any]] = []
    for index, item in enumerate(retained):
        name = "classes.dex" if index == 0 else f"classes{index + 1}.dex"
        final_path = out_dir / name
        os.replace(item["output_path"], final_path)
        verification = verify_dex(final_path, package, min_classes=min_classes, target_packages=target_packages)
        # A fresh header check alone must not erase the repair-level verdict:
        # a repaired truncated/stub/wrong-package DEX stays incomplete.
        item_complete = bool(item.get("complete")) and bool(verification.get("complete"))
        if item_complete:
            status = "complete"
        elif item.get("truncated"):
            status = "truncated"
        elif verification.get("status") == "invalid":
            status = "invalid"
        else:
            status = "partial"
        reasons: list[str] = []
        for reason in list(item.get("reasons") or []) + list(verification.get("reasons") or []):
            if reason not in reasons:
                reasons.append(reason)
        assessment = dict(verification.get("assessment") or {})
        assessment["complete"] = item_complete
        assessment["truncated"] = bool(item.get("truncated"))
        assessment["reasons"] = reasons
        entry = {
            "name": name,
            "path": str(final_path),
            "sha256": item["sha256"],
            "size": verification["size"],
            "class_defs_size": verification.get("class_defs_size", 0),
            "total_classes": verification.get("total_classes", 0),
            "package_classes": verification.get("package_classes", 0),
            "classes_with_code": verification.get("classes_with_code", 0),
            "holes": verification.get("holes", 0),
            "dex_version": verification.get("dex_version"),
            "status": status,
            "complete": item_complete,
            "content_complete": bool(verification.get("content_complete")),
            "stub": bool(item.get("stub")),
            "shell_like": bool(item.get("shell_like")),
            "truncated": bool(item.get("truncated")),
            "reasons": reasons,
            "assessment": assessment,
            "source_path": item["source_path"],
        }
        files.append(entry)
        manifest.append(entry)
    kept_paths = {item["output_path"] for item in retained}
    for item in repaired:
        if item["output_path"] not in kept_paths:
            try:
                Path(item["output_path"]).unlink(missing_ok=True)
            except OSError:
                pass
    # Remove any leftover temporary files that were duplicates or stubs.
    for leftover in out_dir.glob("_tmp_*.dex"):
        try:
            leftover.unlink(missing_ok=True)
        except OSError:
            pass
    manifest_path = out_dir / "manifest.json"
    current_paths = {Path(item['path']).resolve() for item in files}
    removed_stale = []
    for path, digest in previous_owned.items():
        if path not in current_paths and path.is_file() and sha256_file(path) == digest:
            path.unlink()
            removed_stale.append(str(path))
    from datetime import datetime, timezone

    manifest_data = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "output_dir": str(out_dir),
        "files": manifest,
        "duplicates": duplicates,
        "skipped": skipped,
        "removed_stale_files": removed_stale,
        "runtime_snapshot_selection": runtime_variants,
    }
    with open(manifest_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(manifest_data, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    total_classes = sum(item.get("total_classes", 0) for item in files)
    # Overall verdict uses the same structural/target split as
    # ``verify_android_dex``: every usable file must be structurally complete,
    # and (when a package is known) at least one file must contain it.  Runtime
    # DEX files without app-package classes are legitimate multi-DEX members,
    # not failures.  Stub/shell files retained for inspection do not veto a
    # successfully recovered target.
    usable = [item for item in files if not item.get("stub") and not item.get("shell_like")]
    files_complete = bool(usable) and all(
        bool(item.get("content_complete")) and not item.get("truncated") and item.get("status") != "invalid"
        for item in usable
    )
    target_complete = any(bool(item.get("complete")) for item in usable)
    overall_complete = bool(files_complete and target_complete)
    return {
        "output_dir": str(out_dir),
        "manifest_path": str(manifest_path),
        "files": files,
        "duplicates": duplicates,
        "skipped": skipped,
        "removed_stale_files": removed_stale,
        "runtime_snapshot_selection": runtime_variants,
        "total_classes": total_classes,
        "complete": overall_complete,
        "files_complete": files_complete,
        "target_complete": target_complete,
        "status": "complete" if overall_complete else "partial",
    }


def dex_summary_for_apk_entry(entry_size: int, header_bytes: bytes) -> dict[str, Any]:
    header = parse_dex_header(header_bytes)
    if header is None:
        return {
            "header": None,
            "packed_stub": None,
            "encrypted_tail_bytes": 0,
        }
    tail = max(0, entry_size - (header.data_off + header.data_size))
    # Loader DEX files can be very large while containing only a handful of
    # classes (the real code is encrypted in the padding/extra sections).
    bytes_per_class = entry_size / header.class_defs_size if header.class_defs_size else entry_size
    packed_stub = (
        header.class_defs_size <= 10
        or (header.class_defs_size <= 100 and entry_size > 1024 * 1024)
        or (entry_size > 4 * 1024 * 1024 and bytes_per_class > 256 * 1024)
    )
    return {
        "header": header.to_dict(),
        "packed_stub": packed_stub,
        "bytes_per_class": int(bytes_per_class),
        "encrypted_tail_bytes": tail,
    }
