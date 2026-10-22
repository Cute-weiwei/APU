from __future__ import annotations

import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from backend.agents import AgentStore
from backend.config import BackendConfig
from backend.db import Database
from backend.mcp import McpStore
from backend.packages import PackageError, import_package
from backend.providers import ProviderStore
from backend.skills import SkillStore


def make_zip(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


class PackageImportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.config = BackendConfig.load(data_dir=self.temp.name)
        self.config.ensure_dirs()
        self.db = Database(self.config.db_path)
        self.db.initialize()
        self.providers = ProviderStore(self.config, self.db)
        self.provider = self.providers.create(
            {
                "name": "Package Provider",
                "protocol": "openai",
                "base_url": "https://example.test",
                "model": "test-model",
                "api_key": "test-key",
            }
        )
        self.skills = SkillStore(self.config, self.db)
        self.mcps = McpStore(self.config, self.db)
        self.agents = AgentStore(self.config, self.db, self.providers, self.skills, self.mcps)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _package(self) -> bytes:
        return make_zip(
            {
                "skills/pkg-skill/SKILL.md": "---\nname: Package Skill\ndescription: From a ZIP\n---\n\nUse this skill.\n",
                "mcp/echo.json": json.dumps(
                    {
                        "id": "pkg-echo",
                        "name": "Package Echo",
                        "transport": "stdio",
                        "command": "python3",
                        "args": ["-c", "print(1)"],
                    }
                ),
                "agents/pkg-agent.json": json.dumps(
                    {
                        "id": "pkg-agent",
                        "name": "Package Agent",
                        "provider_id": self.provider.id,
                        "skill_ids": ["pkg-skill"],
                        "mcp_ids": ["pkg-echo"],
                        "system_prompt": "Imported from a package.",
                    }
                ),
            }
        )

    def _import(self, payload: bytes) -> dict:
        return import_package(
            payload,
            filename="package.zip",
            skills_store=self.skills,
            mcp_store=self.mcps,
            agent_store=self.agents,
            providers_store=self.providers,
        )

    def test_import_all_types_and_skip_on_reimport(self) -> None:
        result = self._import(self._package())
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["summary"]["installed"], 3)
        self.assertEqual(len(result["installed"]["skills"]), 1)
        self.assertEqual(len(result["installed"]["mcps"]), 1)
        self.assertEqual(len(result["installed"]["agents"]), 1)
        self.assertIsNotNone(self.skills.get("pkg-skill"))
        self.assertIsNotNone(self.mcps.get("pkg-echo"))
        agent = self.agents.get("pkg-agent")
        self.assertIsNotNone(agent)
        self.assertEqual(agent.skill_ids, ["pkg-skill"])
        self.assertEqual(agent.mcp_ids, ["pkg-echo"])

        again = self._import(self._package())
        self.assertEqual(again["summary"]["installed"], 0)
        self.assertEqual(again["summary"]["skipped"], 3)
        self.assertEqual(again["summary"]["errors"], 0)

    def test_rejects_path_traversal(self) -> None:
        with self.assertRaises(PackageError):
            self._import(make_zip({"../outside.txt": "no"}))

    def test_rejects_package_without_items(self) -> None:
        with self.assertRaises(PackageError):
            self._import(make_zip({"README.txt": "nothing to install"}))


if __name__ == "__main__":
    unittest.main()
