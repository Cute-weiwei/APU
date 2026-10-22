from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from apk_unpack.setup import apply_plan, build_plan


class SetupTests(unittest.TestCase):
    def test_plan_apply_and_uninstall(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            claude_dir = root / "claude"
            with mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(claude_dir)}):
                plan = build_plan(project_dir=project)
                self.assertFalse(plan["uninstall"])
                actions = {item["action"] for item in plan["changes"]}
                self.assertIn("copy_skill", actions)
                self.assertIn("merge_mcp", actions)
                self.assertFalse((project / ".mcp.json").exists())
                applied = apply_plan(plan)
                self.assertTrue(applied["ok"])
                skill_dest = claude_dir / "skills" / "unpack-android-apk"
                self.assertTrue((skill_dest / "SKILL.md").is_file())
                self.assertTrue((skill_dest / ".apu-managed.json").is_file())
                mcp = json.loads((project / ".mcp.json").read_text(encoding="utf-8"))
                self.assertIn("apk-unpack", mcp["mcpServers"])

                # Re-applying backs up the existing skill outside the skills root,
                # so clients do not discover the backup as a second skill.
                apply_plan(plan)
                self.assertTrue((skill_dest / "SKILL.md").is_file())
                self.assertFalse(list((claude_dir / "skills").glob("unpack-android-apk.apu.bak-*")))
                self.assertTrue(list((claude_dir / ".apu-backups").glob("unpack-android-apk-*")))

                uninstall = build_plan(project_dir=project, uninstall=True)
                result = apply_plan(uninstall)
                self.assertTrue(result["ok"])
                self.assertFalse(skill_dest.exists())
                mcp = json.loads((project / ".mcp.json").read_text(encoding="utf-8"))
                self.assertNotIn("apk-unpack", mcp.get("mcpServers", {}))

    def test_generic_client_returns_instructions(self) -> None:
        plan = build_plan(client="generic")
        self.assertIn("instructions", plan)
        self.assertIn("mcpServers", plan["instructions"]["mcp"])


if __name__ == "__main__":
    unittest.main()
