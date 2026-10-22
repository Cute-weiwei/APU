from __future__ import annotations

import math
import os
import time
from pathlib import Path
from typing import Any, Iterable

from ..config import Config
from ..domain.errors import fail
from ..domain.models import MapRegion
from .adb import AdbProvider
from .process import ProcessInspector

PAGE = 4096
DEFAULT_CHUNK = 8 * 1024 * 1024


class MemoryReader:
    def __init__(self, adb: AdbProvider, process: ProcessInspector, config: Config):
        self.adb = adb
        self.process = process
        self.config = config

    # ------------------------------------------------------------------ small reads
    def read_small(self, serial: str, pid: int, address: int, size: int, tmp_dir: Path) -> bytes:
        tmp_dir.mkdir(parents=True, exist_ok=True)
        local = tmp_dir / f"read_{int(time.time() * 1000)}_{address:x}.bin"
        command = f"dd if=/proc/{int(pid)}/mem bs=1 skip={int(address)} count={int(size)} 2>/dev/null"
        result = self.adb.exec_out(serial, command, local, timeout=60)
        try:
            if local.is_file() and local.stat().st_size >= size:
                return local.read_bytes()[:size]
            raise fail(
                "dump_incomplete",
                f"short read from /proc/{pid}/mem at {address:#x} ({size} bytes)",
                details={"address": address, "size": size, "returncode": result.returncode, "stderr": result.stderr[-1000:]},
            )
        finally:
            local.unlink(missing_ok=True)

    # ------------------------------------------------------------------ dd primitives
    def _dd_to_remote(
        self,
        serial: str,
        pid: int,
        aligned: int,
        length: int,
        bs: int,
        remote: str,
    ) -> int | None:
        skip = aligned // bs
        count = math.ceil(length / bs)
        command = (
            f"dd if=/proc/{int(pid)}/mem of={remote} bs={bs} "
            f"skip={skip} count={count} 2>/dev/null"
        )
        self.adb.shell(serial, command, timeout=300)
        return self.adb.stat_size(serial, remote)

    def dump_range(
        self,
        serial: str,
        pid: int,
        start: int,
        size: int,
        out_path: str | Path,
        *,
        remote_dir: str,
        chunk_size: int = DEFAULT_CHUNK,
        fast: bool = False,
        strict: bool = True,
    ) -> dict[str, Any]:
        if size <= 0:
            Path(out_path).write_bytes(b"")
            return {"path": str(out_path), "size": 0, "read_modes": [], "holes": 0, "complete": True}

        aligned = start & ~(PAGE - 1)
        prefix = start - aligned
        total = prefix + size
        pages = math.ceil(total / PAGE)
        ladder = [4096, 1024] if fast else [4096, 1024, 64, 1]
        remote_base = remote_dir.rstrip("/")
        read_modes: list[dict[str, Any]] = []
        holes = 0
        written = 0
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        hole_regions: list[dict[str, int]] = []
        with open(out_path, "wb") as sink:
            page_offset = 0
            remaining = size
            chunk_index = 0
            while page_offset < pages:
                chunk_pages = min(pages - page_offset, max(1, chunk_size // PAGE))
                chunk_length = chunk_pages * PAGE
                aligned_addr = aligned + page_offset * PAGE
                chunk_data = None
                used_bs = None
                for bs in ladder:
                    remote = f"{remote_base}/chunk_{os.getpid()}_{chunk_index}_{bs}.bin"
                    try:
                        actual = self._dd_to_remote(serial, pid, aligned_addr, chunk_length, bs, remote)
                        if actual and actual >= chunk_length:
                            local = Path(str(out_path) + f".chunk{chunk_index}")
                            pull = self.adb.pull(serial, remote, local)
                            if pull.ok and local.is_file() and local.stat().st_size >= chunk_length:
                                chunk_data = local.read_bytes()[:chunk_length]
                                used_bs = bs
                            local.unlink(missing_ok=True)
                    finally:
                        self.adb.shell(serial, f"rm -f {remote} 2>/dev/null", timeout=15)
                    if chunk_data is not None:
                        break
                if chunk_data is None:
                    if strict:
                        raise fail(
                            "dump_incomplete",
                            f"dd failed for {chunk_length} bytes at {aligned_addr:#x}",
                            details={"address": aligned_addr, "length": chunk_length, "pid": pid},
                        )
                    chunk_data = b"\x00" * chunk_length
                    holes += chunk_length
                carry = prefix if chunk_index == 0 else 0
                usable = chunk_data[carry:]
                usable = usable[:remaining]
                if used_bs is None and usable:
                    hole_regions.append(
                        {"offset": written, "address": aligned_addr + carry, "size": len(usable)}
                    )
                sink.write(usable)
                written += len(usable)
                remaining -= len(usable)
                read_modes.append(
                    {
                        "address": aligned_addr,
                        "bytes": chunk_length,
                        "bs": used_bs,
                        "data_offset": carry,
                        "hole": used_bs is None,
                    }
                )
                page_offset += chunk_pages
                chunk_index += 1
                if remaining <= 0:
                    break
        complete = holes == 0 and written == size
        return {
            "path": str(out_path),
            "size": written,
            "expected_size": size,
            "read_modes": read_modes,
            "holes": holes,
            "hole_regions": hole_regions,
            "complete": complete,
            "coverage": {
                "expected_bytes": size,
                "written_bytes": written,
                "hole_bytes": holes,
                "hole_ratio": round(holes / size, 4) if size else 0.0,
                "chunks": len(read_modes),
            },
        }

    def dump_virtual_range(
        self,
        serial: str,
        pid: int,
        start: int,
        size: int,
        out_path: str | Path,
        regions: Iterable[MapRegion],
        *,
        remote_dir: str,
        fast: bool = False,
        strict: bool = False,
    ) -> dict[str, Any]:
        """Dump a virtual range that may span multiple mmap regions."""

        end = start + size
        ordered = sorted(regions, key=lambda item: item.start)
        intersecting = [item for item in ordered if item.end > start and item.start < end]
        if len(intersecting) == 1:
            region = intersecting[0]
            if region.readable and region.start <= start and region.end >= end:
                return self.dump_range(
                    serial,
                    pid,
                    start,
                    size,
                    out_path,
                    remote_dir=remote_dir,
                    fast=fast,
                    strict=strict,
                )
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        holes = 0
        written = 0
        segments: list[dict[str, Any]] = []
        hole_regions: list[dict[str, int]] = []
        with open(out_path, "wb") as sink:
            cursor = start
            for region in intersecting:
                segment_start = max(cursor, region.start)
                segment_end = min(end, region.end)
                if segment_start > cursor:
                    gap = segment_start - cursor
                    sink.write(b"\x00" * gap)
                    hole_regions.append({"offset": written, "address": cursor, "size": gap})
                    holes += gap
                    written += gap
                    segments.append({"type": "gap", "start": cursor, "end": segment_start, "size": gap})
                if segment_end <= segment_start:
                    continue
                if not region.readable:
                    gap = segment_end - segment_start
                    sink.write(b"\x00" * gap)
                    hole_regions.append({"offset": written, "address": segment_start, "size": gap})
                    holes += gap
                    written += gap
                    segments.append(
                        {"type": "unreadable", "start": segment_start, "end": segment_end, "size": gap, "perms": region.perms}
                    )
                else:
                    temp = Path(str(out_path) + f".seg{len(segments)}")
                    report = self.dump_range(
                        serial,
                        pid,
                        segment_start,
                        segment_end - segment_start,
                        temp,
                        remote_dir=remote_dir,
                        fast=fast,
                        strict=strict,
                    )
                    data = temp.read_bytes() if temp.is_file() else b""
                    temp.unlink(missing_ok=True)
                    for hole in report.get("hole_regions") or []:
                        hole_regions.append(
                            {
                                "offset": written + int(hole.get("offset") or 0),
                                "address": int(hole.get("address") or segment_start),
                                "size": int(hole.get("size") or 0),
                            }
                        )
                    sink.write(data)
                    written += len(data)
                    holes += report.get("holes", 0)
                    segments.append(
                        {
                            "type": "mapped",
                            "start": segment_start,
                            "end": segment_end,
                            "size": len(data),
                            "complete": report.get("complete"),
                            "path": region.path,
                        }
                    )
                cursor = segment_end
            if cursor < end:
                gap = end - cursor
                sink.write(b"\x00" * gap)
                hole_regions.append({"offset": written, "address": cursor, "size": gap})
                holes += gap
                written += gap
                segments.append({"type": "gap", "start": cursor, "end": end, "size": gap})
        return {
            "path": str(out_path),
            "size": written,
            "expected_size": size,
            "holes": holes,
            "hole_regions": hole_regions,
            "complete": holes == 0 and written == size,
            "segments": segments,
            "coverage": {
                "expected_bytes": size,
                "written_bytes": written,
                "hole_bytes": holes,
                "hole_ratio": round(holes / size, 4) if size else 0.0,
                "segments": len(segments),
            },
        }

    # ------------------------------------------------------------------ region ranking
    @staticmethod
    def score_region(region: MapRegion, shell: str | None = None) -> MapRegion:
        score = 0
        reasons: list[str] = []
        path = (region.path or "").lower()
        if "dalvik-dex" in path:
            score += 100
            reasons.append("dalvik-DEX ashmem (+100)")
        if "libc_malloc" in path:
            score += 50
            reasons.append("libc_malloc (+50)")
        if "[heap]" in path:
            score += 30
            reasons.append("heap (+30)")
        if "dalvik-main space" in path:
            score += 25
            reasons.append("dalvik-main space (+25)")
        if "anon:mem" in path:
            score += 20
            reasons.append("anon:Mem (+20)")
        if region.readable and path.endswith((".dex", ".apk", ".jar", ".vdex", ".oat", ".zip")):
            # Read-only mapped DEX/APK files are safe to scan with /proc/pid/mem
            # and often contain payloads the anonymous-region heuristics miss.
            score += 60
            reasons.append("read-only DEX/APK file mapping (+60)")
        if region.perms.startswith("rw") and not path:
            score += 15
            reasons.append("rw anonymous (+15)")
        megabytes = region.size / (1024 * 1024)
        if 10 <= megabytes <= 80:
            score += 20
            reasons.append("10-80 MiB (+20)")
        elif 5 <= megabytes < 10:
            score += 10
            reasons.append("5-10 MiB (+10)")
        elif megabytes > 100:
            score += 5
            reasons.append(">100 MiB (+5)")
        for token, penalty in (("stack", -100), ("vvar", -100), ("vdso", -100), ("cfi shadow", -100), ("gralloc", -50)):
            if token in path:
                score += penalty
                reasons.append(f"{token} ({penalty})")
        if "dalvik-dex" not in path and not region.perms.startswith("rw"):
            score -= 40
            reasons.append("not readable/writable anonymous (-40)")
        region.score = score
        region.score_reasons = reasons
        return region

    def rank_regions(
        self,
        regions: Iterable[MapRegion],
        *,
        shell: str | None = None,
        include_read_only_dex: bool = True,
    ) -> list[MapRegion]:
        ranked: list[MapRegion] = []
        for region in regions:
            if region.size <= 0:
                continue
            if not region.readable:
                continue
            scored = self.score_region(region, shell)
            path = (region.path or "").lower()
            if not include_read_only_dex and not region.perms.startswith("rw") and "dalvik-dex" not in path:
                continue
            if scored.score > 0:
                ranked.append(scored)
        ranked.sort(key=lambda item: (item.score, item.size), reverse=True)
        return ranked

    @staticmethod
    def zero_ratio(
        path: str | Path,
        sample_size: int = 4 * 1024 * 1024,
        *,
        segments: int = 8,
    ) -> float:
        """Fraction of zero bytes over multiple segments spread across the file.

        The old implementation read only the first 64 KiB, so a real DEX at the
        start of a mostly-zero region made the whole region look non-zero and a
        zero-filled tail went unnoticed.  Sample several evenly spaced windows
        (or the whole file when it is small) instead.
        """

        try:
            size = Path(path).stat().st_size
        except OSError:
            return 0.0
        if size <= 0:
            return 1.0
        budget = max(0, int(sample_size))
        if budget == 0 or size <= budget:
            try:
                with open(path, "rb") as handle:
                    data = handle.read()
            except OSError:
                return 0.0
            return (data.count(0) / len(data)) if data else 1.0
        window_count = max(1, int(segments))
        window = max(1, budget // window_count)
        total = 0
        zeros = 0
        try:
            with open(path, "rb") as handle:
                for index in range(window_count):
                    # Spread windows across the whole file, including the tail.
                    if window_count == 1:
                        offset = 0
                    else:
                        offset = int((size - window) * index / (window_count - 1))
                    handle.seek(max(0, offset))
                    data = handle.read(window)
                    total += len(data)
                    zeros += data.count(0)
        except OSError:
            return 0.0
        return (zeros / total) if total else 1.0

    @staticmethod
    def looks_like_dex_magic(path: str | Path) -> bool:
        try:
            with open(path, "rb") as handle:
                return handle.read(4) == b"dex\n"
        except OSError:
            return False
