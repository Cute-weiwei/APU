from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from apk_unpack.config import Config
from apk_unpack.domain.models import MapRegion
from apk_unpack.providers.memory import MemoryReader
from apk_unpack.providers.process import ProcessInspector

from tests.fixtures import maps_fixture


def result(stdout: str = "") -> SimpleNamespace:
    return SimpleNamespace(ok=True, stdout=stdout, stderr="", returncode=0, missing=False, timed_out=False)


class FakeAdb:
    def __init__(self, maps: str = "", pidof: list[int] | None = None):
        self.maps_text = maps
        self.pidof_value = [123] if pidof is None else pidof

    def shell(self, serial: str, command: str, timeout=None) -> SimpleNamespace:
        if "maps" in command:
            return result(self.maps_text)
        if "status" in command:
            return result(
                "Name:\tcom.example\nState:\tS (sleeping)\nTracerPid:\t0\nThreads:\t12\nVmRSS:\t 100000 kB\n"
            )
        return result()

    def pidof(self, serial: str, package: str) -> list[int]:
        return self.pidof_value

    def stat_size(self, serial: str, path: str) -> int:
        return 4096

    def pull(self, serial: str, remote: str, local: str) -> SimpleNamespace:
        Path(local).write_bytes(b"X" * 4096)
        return result()


class PsFallbackAdb(FakeAdb):
    def __init__(self, ps_output: str):
        super().__init__(pidof=[])
        self.ps_output = ps_output

    def shell(self, serial: str, command: str, timeout=None) -> SimpleNamespace:
        if "ps -A" in command:
            return result(self.ps_output)
        return super().shell(serial, command, timeout=timeout)


class DumpReader(MemoryReader):
    def _dd_to_remote(self, serial, pid, aligned, length, bs, remote):  # type: ignore[override]
        return length


class VirtualReader(MemoryReader):
    def dump_range(self, serial, pid, start, size, out_path, **kwargs):  # type: ignore[override]
        Path(out_path).write_bytes(b"Y" * size)
        return {"path": str(out_path), "size": size, "holes": 0, "complete": True}


class HoleReader(MemoryReader):
    def _dd_to_remote(self, serial, pid, aligned, length, bs, remote):  # type: ignore[override]
        return 0


class ProcessFallbackTests(unittest.TestCase):
    def test_find_pid_falls_back_to_ps_when_pidof_is_empty(self) -> None:
        adb = PsFallbackAdb("u0_a50  1234  1546  12345  6789  S com.example.hidden\n")
        inspector = ProcessInspector(adb)  # type: ignore[arg-type]
        self.assertEqual(inspector.find_pid("serial", "com.example.hidden"), 1234)

    def test_find_pid_falls_back_to_args_for_truncated_names(self) -> None:
        adb = PsFallbackAdb(
            "u0_a50  4321  1546  12345  6789  S com.example.hidd --main com.example.hidden\n"
        )
        inspector = ProcessInspector(adb)  # type: ignore[arg-type]
        self.assertEqual(inspector.find_pid("serial", "com.example.hidden"), 4321)


class MemoryReaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = Config.load(runs_dir=self.root / "runs")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_maps_parser_and_ranking(self) -> None:
        adb = FakeAdb(maps_fixture())
        inspector = ProcessInspector(adb)  # type: ignore[arg-type]
        regions = inspector.maps("serial", 123)
        self.assertEqual(len(regions), 5)
        self.assertTrue(any("dalvik-DEX data (deleted)" in region.path for region in regions))
        reader = MemoryReader(adb, inspector, self.config)  # type: ignore[arg-type]
        ranked = reader.rank_regions(regions, shell="ijiami")
        self.assertIn("dalvik-dex", ranked[0].path.lower())
        self.assertGreater(ranked[0].score, ranked[1].score)
        self.assertFalse(any("[stack]" in region.path for region in ranked))

    def test_dump_range_handles_unaligned_start(self) -> None:
        adb = FakeAdb()
        inspector = ProcessInspector(adb)  # type: ignore[arg-type]
        reader = DumpReader(adb, inspector, self.config)  # type: ignore[arg-type]
        output = self.root / "out.bin"
        report = reader.dump_range(
            "serial",
            123,
            0x1003,
            1000,
            output,
            remote_dir="/tmp/apu",
            chunk_size=4096,
        )
        self.assertEqual(report["size"], 1000)
        self.assertEqual(output.stat().st_size, 1000)
        self.assertTrue(report["complete"])

    def test_virtual_range_zero_fills_mmap_gap(self) -> None:
        adb = FakeAdb()
        inspector = ProcessInspector(adb)  # type: ignore[arg-type]
        reader = VirtualReader(adb, inspector, self.config)  # type: ignore[arg-type]
        regions = [
            MapRegion(0x1000, 0x2000, "rw-p", path="[anon:a]"),
            MapRegion(0x3000, 0x4000, "rw-p", path="[anon:b]"),
        ]
        output = self.root / "virtual.bin"
        report = reader.dump_virtual_range(
            "serial", 123, 0x1000, 0x3000, output, regions, remote_dir="/tmp/apu"
        )
        data = output.read_bytes()
        self.assertEqual(len(data), 0x3000)
        self.assertTrue(all(byte == 0x59 for byte in data[:0x1000]))
        self.assertTrue(all(byte == 0x00 for byte in data[0x1000:0x2000]))
        self.assertTrue(all(byte == 0x59 for byte in data[0x2000:0x3000]))
        self.assertEqual(report["holes"], 0x1000)

    def test_zero_ratio(self) -> None:
        path = self.root / "zero.bin"
        path.write_bytes(b"\x00" * 1024)
        self.assertEqual(MemoryReader.zero_ratio(path), 1.0)

    def test_zero_ratio_samples_beyond_first_64k(self) -> None:
        path = self.root / "tail-zero.bin"
        # Real data at the start, a zero-filled tail: the old first-64KiB
        # sampler reported ~0 and scanned a dump that was mostly a hole.
        path.write_bytes(b"\xAA" * (64 * 1024) + b"\x00" * (1024 * 1024))
        ratio = MemoryReader.zero_ratio(path, sample_size=256 * 1024, segments=8)
        self.assertGreater(ratio, 0.75)
        self.assertLess(ratio, 1.0)

    def test_dump_range_reports_zero_fill_holes(self) -> None:
        adb = FakeAdb()
        inspector = ProcessInspector(adb)  # type: ignore[arg-type]
        reader = HoleReader(adb, inspector, self.config)  # type: ignore[arg-type]
        output = self.root / "holes.bin"
        report = reader.dump_range(
            "serial",
            123,
            0x1000,
            8192,
            output,
            remote_dir="/tmp/apu",
            chunk_size=4096,
            strict=False,
        )
        self.assertEqual(report["size"], 8192)
        self.assertEqual(report["holes"], 8192)
        self.assertFalse(report["complete"])
        self.assertTrue(report["hole_regions"])
        self.assertEqual(report["coverage"]["hole_bytes"], 8192)

    def test_virtual_range_reports_hole_offsets(self) -> None:
        adb = FakeAdb()
        inspector = ProcessInspector(adb)  # type: ignore[arg-type]
        reader = VirtualReader(adb, inspector, self.config)  # type: ignore[arg-type]
        regions = [
            MapRegion(0x1000, 0x2000, "rw-p", path="[anon:a]"),
            MapRegion(0x3000, 0x4000, "rw-p", path="[anon:b]"),
        ]
        output = self.root / "virtual-holes.bin"
        report = reader.dump_virtual_range(
            "serial", 123, 0x1000, 0x3000, output, regions, remote_dir="/tmp/apu"
        )
        self.assertFalse(report["complete"])
        self.assertEqual(report["hole_regions"][0]["address"], 0x2000)
        self.assertEqual(report["hole_regions"][0]["offset"], 0x1000)

    def test_read_only_dex_file_mapping_is_scanned(self) -> None:
        maps = "\n".join(
            [
                "7f0000000000-7f0000100000 r--p 00000000 08:01 123 /data/app/com.example/base.apk",
                "7f0002000000-7f0002100000 r--p 00000000 08:01 456 /system/lib64/libc.so",
            ]
        )
        adb = FakeAdb(maps)
        inspector = ProcessInspector(adb)  # type: ignore[arg-type]
        reader = MemoryReader(adb, inspector, self.config)  # type: ignore[arg-type]
        ranked = reader.rank_regions(inspector.maps("serial", 123))
        self.assertTrue(any(region.path.endswith("base.apk") for region in ranked))
        self.assertFalse(any(region.path.endswith("libc.so") for region in ranked))


class MultiPidTests(unittest.TestCase):
    def test_main_process_is_preferred_over_subprocess(self) -> None:
        ps = (
            "u0_a50  2000  1  S com.example:remote com.example:remote\n"
            "u0_a50  1234  1  S com.example com.example\n"
        )
        inspector = ProcessInspector(PsFallbackAdb(ps))  # type: ignore[arg-type]
        selection = inspector.find_pid_candidates("serial", "com.example")
        self.assertEqual(selection["main_pid"], 1234)
        self.assertEqual(inspector.find_pid("serial", "com.example"), 1234)
        roles = {item["pid"]: item["role"] for item in selection["candidates"]}
        self.assertEqual(roles[1234], "main")
        self.assertEqual(roles[2000], "subprocess")

    def test_explicit_pid_is_validated_against_cmdline(self) -> None:
        class CmdlineAdb(PsFallbackAdb):
            def __init__(self, cmdline: str):
                super().__init__("")
                self.cmdline_value = cmdline

            def shell(self, serial: str, command: str, timeout=None):
                if "cmdline" in command:
                    return result(self.cmdline_value)
                return super().shell(serial, command, timeout=timeout)

        inspector = ProcessInspector(CmdlineAdb("com.example"))

        good = inspector.validate_pid("serial", 1234, "com.example")
        self.assertTrue(good["valid"])
        self.assertTrue(good["is_main"])
        other = ProcessInspector(CmdlineAdb("com.other"))  # type: ignore[arg-type]
        self.assertFalse(other.validate_pid("serial", 1234, "com.example")["valid"])


if __name__ == "__main__":
    unittest.main()
