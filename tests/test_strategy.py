from __future__ import annotations

import unittest

from apk_unpack.application.strategy import recommend_strategy


def inspection(
    shell: str,
    *,
    layers: list[str] | None = None,
    abis: list[str] | None = None,
    frameworks: list[str] | None = None,
    packed: bool = True,
) -> dict:
    layers = layers or ([shell] if shell != "unknown" else [])
    return {
        "packing": {
            "primary": shell,
            "layers": [{"shell": item} for item in layers],
            "packed": packed,
        },
        "abis": abis or ["arm64-v8a", "x86_64"],
        "frameworks": [{"name": item} for item in (frameworks or [])],
        "limitations": [],
    }


DEVICE = {"abi": "x86_64", "root": {"available": True}}


class StrategyTests(unittest.TestCase):
    def test_bangcle_goes_straight_to_memory(self) -> None:
        result = recommend_strategy(inspection("bangcle"), DEVICE)
        self.assertEqual(result["primary"], "memory_dd")
        self.assertIn("memory_dd_retry", result["fallbacks"])
        self.assertIn("freeze_dd", result["fallbacks"])
        self.assertTrue(any("frida" in item for item in result["do_not_attempt"]))
        self.assertTrue(any("fake dlsym" in risk for risk in result["risks"]))

    def test_360_uses_mcookie_and_forbids_dd(self) -> None:
        result = recommend_strategy(inspection("360"), DEVICE)
        self.assertEqual(result["primary"], "frida_mcookie")
        self.assertIn("memory_dd", result["do_not_attempt"])

    def test_360_secneo_mentions_inner_bypass(self) -> None:
        result = recommend_strategy(inspection("360", layers=["360", "secneo"]), DEVICE)
        self.assertEqual(result["primary"], "frida_mcookie")
        self.assertTrue(any("SecNeo" in note for note in result["notes"]))
        self.assertTrue(any(step.get("requires") for step in result["steps"]))

    def test_360_tracer_nonzero_adds_spawn_fallback(self) -> None:
        result = recommend_strategy(inspection("360"), DEVICE, {"tracer_pid": 99})
        self.assertIn("frida_mcookie_spawn_anti_kill", result["fallbacks"])
        self.assertIn("arm64_device_fallback", result["fallbacks"])

    def test_live_process_status_drives_tracer_fallback(self) -> None:
        result = recommend_strategy(inspection("360"), DEVICE, {"pid":42,"status":{"tracer_pid":99}})
        self.assertIn("frida_mcookie_spawn_anti_kill", result["fallbacks"])
        self.assertIn("arm64_device_fallback", result["fallbacks"])

    def test_tencent_uses_disk_pull(self) -> None:
        result = recommend_strategy(inspection("tencent"), DEVICE)
        self.assertEqual(result["primary"], "disk_pull")

    def test_ijiami_uses_frida_with_spawn_and_memory_fallbacks(self) -> None:
        result = recommend_strategy(inspection("ijiami"), DEVICE)
        self.assertEqual(result["primary"], "frida_inmemory")
        self.assertEqual(result["fallbacks"], ["frida_inmemory_spawn", "memory_dd", "freeze_dd"])

    def test_ijiami_tracer_nonzero_keeps_spawn_then_memory(self) -> None:
        result = recommend_strategy(inspection("ijiami"), DEVICE, {"tracer_pid": 7})
        self.assertEqual(result["primary"], "frida_inmemory")
        self.assertEqual(result["fallbacks"], ["frida_inmemory_spawn", "memory_dd", "freeze_dd"])
        self.assertTrue(any("spawn+anti-kill" in note for note in result["notes"]))

    def test_uni_app_static_route(self) -> None:
        result = recommend_strategy(inspection("ijiami", frameworks=["uni-app"]), DEVICE)
        self.assertEqual(result["primary"], "static_wgt")
        self.assertIn("extract_apk_assets", [step["tool"] for step in result["steps"]])

    def test_unpacked_apk_static_jadx(self) -> None:
        result = recommend_strategy(inspection("unknown", packed=False), DEVICE)
        self.assertEqual(result["primary"], "static_jadx")

    def test_forced_plain_apk_uses_runtime_route(self) -> None:
        result = recommend_strategy(inspection('unknown', packed=False), DEVICE, force_dump=True)
        self.assertEqual(result['primary'], 'frida_inmemory')
        self.assertNotIn('dump_android_dex', result['do_not_attempt'])
        self.assertIn('launch_android_target', [s['tool'] for s in result['steps']])

    def test_force_dump_retains_shell_specific_exclusions(self) -> None:
        bangcle = recommend_strategy(inspection('bangcle', frameworks=['uni-app']), DEVICE, force_dump=True)
        self.assertEqual(bangcle['primary'], 'memory_dd')
        self.assertIn('frida_inmemory', bangcle['do_not_attempt'])
        jiagu = recommend_strategy(inspection('360'), DEVICE, force_dump=True)
        self.assertIn('memory_dd', jiagu['do_not_attempt'])

    def test_arm_only_on_x86_notes_crash_window(self) -> None:
        result = recommend_strategy(inspection("bangcle", abis=["arm64-v8a"]), DEVICE)
        self.assertTrue(any("Houdini" in note for note in result["notes"]))
        self.assertEqual(result["primary"], "memory_dd")


if __name__ == "__main__":
    unittest.main()
