from __future__ import annotations

import json
import os
import stat
import tempfile
import threading
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest import mock

from backend.agents import AgentStore, BUILTIN_AGENT_ID
from backend.config import BackendConfig
from backend.db import Database
from backend.engines import (
    JobContext,
    ProviderOpenAIEngine,
    _fit_anthropic_context,
    _fit_openai_context,
    list_provider_models,
    test_provider,
)
from backend.events import EventBus
from backend.jobs import JobManager
from backend.mcp import McpClient, McpServerConfig, McpStore, _parse_http_body, test_mcp_server, tool_alias
from backend.providers import ProviderConfig, ProviderStore, endpoint_url
from backend.skills import BUILTIN_SKILL_ID, SkillStore


class CatalogCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = mock.patch.dict(os.environ, {}, clear=False)
        self.env.start()
        self.addCleanup(self.env.stop)
        for name in ("DEEPSEEK_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
            os.environ.pop(name, None)
        self.config = BackendConfig.load(data_dir=self.root / "data")
        self.db = Database(self.config.db_path)
        self.db.initialize()
        self.providers = ProviderStore(self.config, self.db)
        self.providers.seed()
        self.skills = SkillStore(self.config, self.db)
        self.skills.seed()
        self.mcps = McpStore(self.config, self.db)
        self.agents = AgentStore(self.config, self.db, self.providers, self.skills, self.mcps)
        self.agents.seed()


class ProviderStoreTests(CatalogCase):
    def test_seed_and_key_storage(self) -> None:
        ids = {provider.id for provider in self.providers.list(include_keys=False)}
        self.assertIn("deepseek-openai", ids)
        self.assertIn("deepseek-anthropic", ids)
        self.assertIn("anthropic-claude", ids)
        self.assertFalse(self.providers.get("deepseek-openai").available)

        self.providers.write_key("deepseek-openai", "sk-test-1234567890")
        provider = self.providers.get("deepseek-openai")
        self.assertTrue(provider.available)
        secret_path = self.providers._key_path("deepseek-openai")
        self.assertTrue(secret_path.is_file())
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(secret_path.stat().st_mode), 0o600)
        row = self.db.get_provider("deepseek-openai")
        self.assertNotIn("sk-test-1234567890", json.dumps(row))
        public = provider.public(admin=True)
        self.assertNotIn("sk-test-1234567890", json.dumps(public))
        self.assertTrue(public["api_key_hint"].endswith("7890"))
        self.assertNotIn("api_key_hint", provider.public(admin=False))

    def test_create_update_clear_delete(self) -> None:
        provider = self.providers.create(
            {
                "name": "Local OpenAI",
                "protocol": "openai",
                "base_url": "https://example.com/v1",
                "model": "model-a",
                "api_key": "sk-local-12345678",
            }
        )
        self.assertTrue(provider.available)
        self.assertEqual(provider.endpoint, "https://example.com/v1/chat/completions")

        updated = self.providers.update(provider.id, {"model": "model-b"})
        self.assertEqual(updated.model, "model-b")
        self.assertTrue(updated.api_key_set)

        cleared = self.providers.update(provider.id, {"clear_api_key": True})
        self.assertFalse(cleared.api_key_set)
        self.assertIsNone(self.providers.read_key(provider.id))

        self.providers.delete(provider.id)
        self.assertIsNone(self.providers.get(provider.id))

    def test_endpoint_urls(self) -> None:
        self.assertEqual(endpoint_url("https://api.deepseek.com", "openai"), "https://api.deepseek.com/chat/completions")
        self.assertEqual(
            endpoint_url("https://api.deepseek.com/anthropic", "anthropic"),
            "https://api.deepseek.com/anthropic/v1/messages",
        )
        self.assertEqual(
            endpoint_url("https://api.anthropic.com", "anthropic"),
            "https://api.anthropic.com/v1/messages",
        )
        self.assertEqual(
            endpoint_url("https://api.openai.com/v1", "openai"),
            "https://api.openai.com/v1/chat/completions",
        )


class ContextTests(CatalogCase):
    def _ctx(self) -> JobContext:
        return JobContext(
            job_id="job_test",
            user_id=1,
            engine="agent-deepseek-openai",
            upload_path=self.root / "target.apk",
            apk_name="target.apk",
            serial=None,
            options={},
            runs_dir=self.root / "runs",
            memory_dir=self.root / "memory",
            work_dir=self.root / "work",
            cancel=threading.Event(),
            emit=lambda *args, **kwargs: None,
            service=None,
            run_id="run_test",
            config=self.config,
        )

    def _provider(self) -> ProviderConfig:
        return ProviderConfig(
            id="p",
            name="p",
            protocol="openai",
            base_url="https://example.com",
            model="m",
            api_key="sk-test-12345678",
            context_window=6000,
            max_tokens=1000,
        )

    def test_openai_trim_drops_old_tool_groups(self) -> None:
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": "system"},
            {"role": "user", "content": "start"},
        ]
        for index in range(30):
            messages.append(
                {
                    "role": "assistant",
                    "content": "x" * 400,
                    "tool_calls": [{"id": str(index), "function": {"name": "f", "arguments": "{}"}}],
                }
            )
            messages.append({"role": "tool", "tool_call_id": str(index), "content": "y" * 800})
        before = len(messages)
        removed = _fit_openai_context(self._ctx(), messages, "system", [], self._provider())
        self.assertGreater(removed, 0)
        self.assertLess(len(messages), before)
        self.assertEqual(messages[0]["role"], "system")
        self.assertEqual(messages[1]["role"], "user")
        if len(messages) > 2:
            self.assertEqual(messages[2]["role"], "assistant")

    def test_anthropic_trim_drops_pairs(self) -> None:
        messages: list[dict[str, Any]] = [{"role": "user", "content": "start"}]
        for index in range(30):
            messages.append(
                {
                    "role": "assistant",
                    "content": [{"type": "tool_use", "id": str(index), "name": "f", "input": {}}],
                }
            )
            messages.append(
                {
                    "role": "user",
                    "content": [{"type": "tool_result", "tool_use_id": str(index), "content": "y" * 800}],
                }
            )
        before = len(messages)
        removed = _fit_anthropic_context(self._ctx(), messages, "system", [], self._provider())
        self.assertGreater(removed, 0)
        self.assertLess(len(messages), before)
        self.assertEqual(messages[0]["role"], "user")
        if len(messages) > 1:
            self.assertEqual(messages[1]["role"], "assistant")

    def test_static_dex_extraction(self) -> None:
        apk = self.root / "plain.apk"
        with zipfile.ZipFile(apk, "w") as archive:
            archive.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 100)
            archive.writestr("classes2.dex", b"dex\n035\x00" + b"\x00" * 100)
        ctx = self._ctx()
        ctx.upload_path = apk
        engine = ProviderOpenAIEngine(self.config, self._provider())
        count = engine._extract_static_dex(ctx)
        self.assertEqual(count, 2)
        target = ctx.run_dir / "dexdump" / "fixed"
        self.assertTrue((target / "classes.dex").is_file())
        self.assertTrue((target / "classes2.dex").is_file())


class ProviderRequestTests(unittest.TestCase):
    def _provider(self, protocol: str = "openai") -> ProviderConfig:
        base = "https://api.deepseek.com/anthropic" if protocol == "anthropic" else "https://api.deepseek.com"
        return ProviderConfig(
            id="p",
            name="p",
            protocol=protocol,
            base_url=base,
            model="deepseek-chat",
            api_key="sk-test-12345678",
        )

    def test_openai_connection_test(self) -> None:
        reply = {"choices": [{"message": {"content": "OK"}}], "usage": {"total_tokens": 3}}
        with mock.patch("backend.engines._post_json", return_value=reply) as post:
            result = test_provider(self._provider())
        self.assertTrue(result["ok"])
        args = post.call_args[0]
        self.assertEqual(args[0], "https://api.deepseek.com/chat/completions")
        self.assertEqual(args[1]["Authorization"], "Bearer sk-test-12345678")
        self.assertEqual(args[2]["model"], "deepseek-chat")

    def test_anthropic_connection_test(self) -> None:
        reply = {"content": [{"type": "text", "text": "OK"}], "usage": {"input_tokens": 2, "output_tokens": 1}}
        with mock.patch("backend.engines._post_json", return_value=reply) as post:
            result = test_provider(self._provider("anthropic"))
        self.assertTrue(result["ok"])
        args = post.call_args[0]
        self.assertEqual(args[0], "https://api.deepseek.com/anthropic/v1/messages")
        self.assertEqual(args[1]["x-api-key"], "sk-test-12345678")
        self.assertEqual(args[1]["Authorization"], "Bearer sk-test-12345678")
        self.assertEqual(args[1]["anthropic-version"], "2023-06-01")

    def test_models_discovery(self) -> None:
        with mock.patch("backend.engines._get_json", return_value={"data": [{"id": "b"}, {"id": "a"}]}) as get:
            result = list_provider_models(self._provider())
        self.assertEqual(result["models"], ["a", "b"])
        self.assertEqual(get.call_args[0][0], "https://api.deepseek.com/models")
        anthropic = list_provider_models(self._provider("anthropic"))
        self.assertEqual(anthropic["source"], "preset")
        self.assertIn("deepseek-chat", anthropic["models"])


class SkillMcpTests(CatalogCase):
    def test_skill_crud_and_resolution(self) -> None:
        builtin = self.skills.get(BUILTIN_SKILL_ID)
        self.assertTrue(builtin["builtin"])
        self.assertGreater(builtin["chars"], 100)
        self.assertGreater(len(self.skills.resolve([BUILTIN_SKILL_ID])), 0)
        with self.assertRaises(ValueError):
            self.skills.delete(BUILTIN_SKILL_ID)

        skill = self.skills.create({"name": "My Skill", "content": "# My Skill\nDo things.", "description": "test"})
        self.assertEqual(skill["source"], "custom")
        updated = self.skills.update(skill["id"], {"content": "# Updated\nNew content."})
        self.assertIn("Updated", updated["content"])
        self.skills.delete(skill["id"])
        self.assertIsNone(self.skills.get(skill["id"]))

    def test_mcp_store_secrets_and_alias(self) -> None:
        server = self.mcps.create(
            {
                "name": "remote",
                "transport": "http",
                "url": "https://example.com/mcp",
                "headers": {"Authorization": "Bearer secret-token"},
                "env": {"TOKEN": "secret-token"},
            }
        )
        self.assertTrue(server.available)
        secret_path = self.mcps._secret_path(server.id)
        self.assertTrue(secret_path.is_file())
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(secret_path.stat().st_mode), 0o600)
        public = server.public(admin=True)
        self.assertNotIn("secret-token", json.dumps(public))
        self.assertIn("Authorization", public["header_names"])
        self.assertTrue(public["has_secrets"])

        cleared = self.mcps.update(server.id, {"clear_secrets": True})
        self.assertFalse(cleared.public(admin=True)["has_secrets"])
        self.assertFalse(secret_path.exists())
        self.mcps.delete(server.id)
        self.assertIsNone(self.mcps.get(server.id))

        alias = tool_alias("some-server", "a/very/long/tool-name-with-many-characters-" * 4)
        self.assertLessEqual(len(alias), 64)
        self.assertTrue(alias.startswith("mcp__"))

    def test_parse_sse_body(self) -> None:
        body = 'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"tools":[]}}\n\n'
        parsed = _parse_http_body(body)
        self.assertEqual(parsed["id"], 1)
        self.assertEqual(parsed["result"], {"tools": []})

    def test_http_mcp_client(self) -> None:
        server_holder: dict[str, Any] = {}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: Any) -> None:
                pass

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                message = json.loads(self.rfile.read(length) or b"{}")
                method = message.get("method")
                if method == "initialize":
                    result: dict[str, Any] = {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "fake", "version": "1"},
                    }
                elif method == "tools/list":
                    result = {
                        "tools": [
                            {
                                "name": "echo",
                                "description": "echo text",
                                "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
                            }
                        ]
                    }
                elif method == "tools/call":
                    text = (message.get("params") or {}).get("arguments", {}).get("text", "")
                    result = {"content": [{"type": "text", "text": text}]}
                else:
                    result = {}
                body = json.dumps({"jsonrpc": "2.0", "id": message.get("id"), "result": result}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server_holder["httpd"] = httpd
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(httpd.shutdown)
        self.addCleanup(httpd.server_close)
        self.addCleanup(thread.join, 2)
        port = httpd.server_address[1]
        server = McpServerConfig(
            id="fake",
            name="fake",
            transport="http",
            url=f"http://127.0.0.1:{port}/mcp",
        )
        result = test_mcp_server(server, timeout_s=5)
        self.assertTrue(result["ok"])
        self.assertEqual([tool["name"] for tool in result["tools"]], ["echo"])

        client = McpClient(server, timeout_s=5)
        try:
            client.connect()
            tools = client.list_tools()
            self.assertEqual(tools[0]["name"], "echo")
            called = client.call_tool("echo", {"text": "hello"})
            self.assertEqual(called["content"][0]["text"], "hello")
        finally:
            client.close()


class AgentEngineTests(CatalogCase):
    def setUp(self) -> None:
        super().setUp()
        self.providers.write_key("deepseek-openai", "sk-a-123456789")
        self.providers.write_key("deepseek-anthropic", "sk-b-123456789")
        self.manager = JobManager(self.config, self.db, EventBus(self.db))
        self.manager.seed_catalog()
        self.manager.refresh_engines()

    def test_provider_agents_and_aliases(self) -> None:
        self.assertIn(BUILTIN_AGENT_ID, self.manager.engines)
        self.assertIn("agent-deepseek-openai", self.manager.engines)
        self.assertIn("agent-deepseek-anthropic", self.manager.engines)
        self.assertTrue(self.manager.engines["agent-deepseek-openai"].available)
        self.assertTrue(self.manager.engines["agent-deepseek-anthropic"].available)
        public = self.manager.engine_public(admin=True)
        self.assertNotIn("sk-a-123456789", json.dumps(public))
        self.assertEqual(self.manager.agents.canonical_engine("agent"), BUILTIN_AGENT_ID)
        self.assertEqual(self.manager.agents.canonical_engine("deepseek"), "agent-deepseek-openai")
        self.assertEqual(self.manager.agents.canonical_engine("claude"), "agent-anthropic-claude")
        self.assertEqual(self.manager.agents.canonical_engine("deepseek-openai"), "agent-deepseek-openai")

    def test_custom_agent_with_skill_and_mcp(self) -> None:
        server = self.manager.mcps.create(
            {"name": "remote", "transport": "http", "url": "https://example.com/mcp"}
        )
        agent = self.manager.agents.create(
            {
                "name": "Custom",
                "provider_id": "deepseek-openai",
                "skill_ids": [BUILTIN_SKILL_ID],
                "mcp_ids": [server.id],
                "system_prompt": "be concise",
            }
        )
        self.manager.refresh_engines()
        engine = self.manager.engines[agent.id]
        self.assertTrue(engine.available)
        self.assertEqual(engine.agent.system_prompt, "be concise")
        self.assertEqual(len(engine.skills), 1)
        self.assertEqual(len(engine.mcps), 1)
        with self.assertRaises(ValueError):
            self.manager.agents.delete("agent-deepseek-openai")
        self.manager.agents.delete(agent.id)
        self.manager.refresh_engines()
        self.assertNotIn(agent.id, self.manager.engines)

    def test_native_agent_toggle(self) -> None:
        agent = self.manager.agents.get(BUILTIN_AGENT_ID)
        self.assertEqual(agent.kind, "native")
        builtin_skill = self.skills.get(BUILTIN_SKILL_ID)
        self.assertTrue(builtin_skill["builtin"])
        updated = self.manager.agents.update(BUILTIN_AGENT_ID, {"enabled": False})
        self.assertFalse(updated.enabled)
        self.manager.refresh_engines()
        self.assertFalse(self.manager.engines[BUILTIN_AGENT_ID].available)
        self.manager.agents.update(BUILTIN_AGENT_ID, {"enabled": True})
        self.manager.refresh_engines()
        self.assertTrue(self.manager.engines[BUILTIN_AGENT_ID].available)

    def test_provider_delete_cascades_agent(self) -> None:
        self.assertIsNotNone(self.db.get_agent("agent-deepseek-openai"))
        self.manager.providers.delete("deepseek-openai")
        self.assertIsNone(self.db.get_agent("agent-deepseek-openai"))


if __name__ == "__main__":
    unittest.main()


class AutoProtocolTests(CatalogCase):
    def test_auto_protocol_falls_back_to_anthropic(self) -> None:
        provider = ProviderConfig(
            id="auto-test",
            name="Auto",
            protocol="auto",
            base_url="https://api.deepseek.com",
            model="deepseek-chat",
            api_key="sk-test",
            context_window=65536,
            max_tokens=4096,
        )
        seen: list[str] = []

        def fake_post(url: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
            seen.append(url)
            if url.endswith("/chat/completions"):
                raise RuntimeError("HTTP 404 (OpenAI endpoint not available)")
            return {"content": [{"type": "text", "text": "OK"}], "usage": {}}

        with mock.patch("backend.engines._post_json", side_effect=fake_post):
            result = test_provider(provider)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["protocol"], "auto")
        self.assertEqual(len(result["attempts"]), 2)
        self.assertFalse(result["attempts"][0]["ok"])
        self.assertTrue(result["attempts"][1]["ok"])
        self.assertEqual(seen[0], "https://api.deepseek.com/chat/completions")
        self.assertEqual(seen[1], "https://api.deepseek.com/v1/messages")

    def test_auto_protocol_falls_back_to_openai(self) -> None:
        provider = ProviderConfig(
            id="auto-test-2",
            name="Auto",
            protocol="auto",
            base_url="https://api.example.com/anthropic",
            model="claude-sonnet-5",
            api_key="sk-test",
        )
        seen: list[str] = []

        def fake_post(url: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
            seen.append(url)
            if url.endswith("/v1/messages"):
                raise RuntimeError("HTTP 404 (Anthropic endpoint not available)")
            return {"choices": [{"message": {"content": "OK"}}], "usage": {}}

        with mock.patch("backend.engines._post_json", side_effect=fake_post):
            result = test_provider(provider)
        self.assertTrue(result["ok"], result)
        self.assertEqual(len(result["attempts"]), 2)
        self.assertEqual(seen[0], "https://api.example.com/anthropic/v1/messages")
        self.assertEqual(seen[1], "https://api.example.com/anthropic/chat/completions")


class UserAdminGuardTests(CatalogCase):
    def test_admin_count_and_delete_user(self) -> None:
        from backend.security import hash_password

        salt, digest = hash_password("admin-pass")
        first = self.db.create_user("admin-one", digest, salt, "admin")
        salt, digest = hash_password("admin-pass")
        second = self.db.create_user("admin-two", digest, salt, "admin")
        salt, digest = hash_password("user-pass")
        normal = self.db.create_user("normal", digest, salt, "user")
        self.assertEqual(self.db.count_admins(), 2)
        self.assertEqual(self.db.count_admins(active_only=False), 2)
        self.db.update_user(second["id"], disabled=1)
        self.assertEqual(self.db.count_admins(), 1)
        self.assertEqual(self.db.count_admins(active_only=False), 2)
        self.db.create_session("hash-one", first["id"], 7)
        self.db.create_session("hash-normal", normal["id"], 7)
        self.db.delete_user(normal["id"])
        self.assertIsNone(self.db.get_user(normal["id"]))
        self.assertIsNone(self.db.get_session("hash-normal"))
        self.assertIsNotNone(self.db.get_session("hash-one"))
        self.db.delete_user(first["id"])
        self.assertIsNone(self.db.get_user(first["id"]))
        self.assertEqual(self.db.count_admins(active_only=False), 1)
