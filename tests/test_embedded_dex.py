from pathlib import Path
from types import SimpleNamespace
from unittest import mock
import threading

from apk_unpack.application.dex_validation import assess_dex
from apk_unpack.domain.errors import AnalysisError
from apk_unpack.providers.dex import scan_file_for_dex
from apk_unpack.domain.models import MapRegion
from tests.fixtures import build_valid_dex
from tests.test_workflow import WorkflowBase


class EmbeddedDexTests(WorkflowBase):
    def test_large_continuation_mapping_is_scanned_for_next_dex(self):
        blob = build_valid_dex("com.example")
        offset = 2 * 1024 * 1024
        data = b"x" * offset + blob
        region = MapRegion(start=0x1000, end=0x1000 + len(data),
                           perms="r--p", offset=0, dev="00:00", inode=0,
                           path="[anon:dalvik-DEX data]")
        def read(serial, pid, start, size, path, **kwargs):
            Path(path).write_bytes(data[:size])
            return {"size": size, "holes": 0, "hole_regions": []}
        self.service.memory = SimpleNamespace(
            read_small=lambda *a: data[:112], dump_range=mock.Mock(side_effect=read),
            zero_ratio=lambda p: 0.0,
        )
        result = self.service._dump_region_candidates(
            self.run, "fake", 42, region, 0, remote_dir="/owned/run",
            fast=True, max_region_bytes=len(data), keep_device_files=False,
        )
        self.assertEqual(len(result["candidates"]), 1)
        self.assertEqual(result["candidates"][0]["vaddr"], 0x1000 + offset)
        self.assertTrue(assess_dex(result["candidates"][0]["local_path"], "com.example").complete)
        self.service.memory.dump_range.assert_called_once()

    def candidate(self, blob):
        region = self.run.raw_dir / "initial-region.bin"
        region.write_bytes(b"x" * 32 + blob[:160])
        candidate = scan_file_for_dex(region, self.run.raw_dir, base_vaddr=0x1000)[0]
        self.assertTrue(candidate["truncated"])
        return candidate

    def complete(self, candidates, limit, cancel=None):
        return self.service._complete_memory_candidates(
            self.run, "fake", 42, candidates, remote_dir="/owned/run", fast=True,
            max_region_bytes=limit, cancel=cancel,
        )

    def test_embedded_header_is_completed_by_its_own_virtual_address(self):
        blob = build_valid_dex("com.example", padding=8192)
        candidate = self.candidate(blob)
        original = Path(candidate["local_path"])
        before = original.read_bytes()
        self.service.process = SimpleNamespace(maps=lambda *a: [])
        def read(serial, pid, start, size, path, maps, **kwargs):
            self.assertEqual((start, size), (0x1020, len(blob)))
            Path(path).write_bytes(blob)
            return {"size": len(blob), "holes": 0, "hole_regions": []}
        reader = mock.Mock(side_effect=read)
        self.service.memory = SimpleNamespace(dump_virtual_range=reader)
        candidates = [candidate]
        reports = self.complete(candidates, len(blob))
        self.assertEqual(reports[0]["status"], "read")
        self.assertFalse(candidates[0]["truncated"])
        self.assertTrue(assess_dex(candidates[0]["local_path"], "com.example").complete)
        self.assertEqual(original.read_bytes(), before)
        reader.assert_called_once()

    def test_completed_span_preserves_holes_and_partial_verdict(self):
        blob = build_valid_dex("com.example", padding=8192)
        candidate = self.candidate(blob)
        offset = blob.index(b"\xa5" * 4096)
        partial = blob[:offset] + b"\0" * 4096 + blob[offset + 4096:]
        self.service.process = SimpleNamespace(maps=lambda *a: [])
        def read(serial, pid, start, size, path, maps, **kwargs):
            Path(path).write_bytes(partial)
            return {"size": len(partial), "holes": 4096,
                    "hole_regions": [{"address": start + offset, "size": 4096}]}
        self.service.memory = SimpleNamespace(dump_virtual_range=read)
        candidates = [candidate]
        self.complete(candidates, len(blob))
        self.assertEqual(candidates[0]["dump_holes"], 4096)
        verdict = assess_dex(candidates[0]["local_path"], "com.example")
        self.assertTrue(verdict.recoverable)
        self.assertFalse(verdict.complete)

    def test_size_limit_and_cancellation_prevent_additional_memory_reads(self):
        blob = build_valid_dex("com.example", padding=8192)
        candidate = self.candidate(blob)
        self.service.memory = mock.Mock()
        candidates = [candidate]
        self.assertEqual(self.complete(candidates, len(blob)-1)[0]["reason"], "candidate_size_cap")
        self.assertIs(candidates[0], candidate)
        event = threading.Event()
        event.set()
        with self.assertRaises(AnalysisError) as caught:
            self.complete(candidates, len(blob), event)
        self.assertEqual(caught.exception.code, "cancelled")
        self.service.memory.dump_virtual_range.assert_not_called()
