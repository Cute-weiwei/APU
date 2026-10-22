from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from backend.agents import AgentSpec, AgentStore
from backend.chat import ChatError, ChatService, ChatToolbox
from backend.config import BackendConfig
from backend.db import Database
from backend.jobs import JobManager
from backend.mcp import McpStore
from backend.providers import ProviderConfig, ProviderStore
from backend.server import _older_than, _path_bytes, _upload_bytes
from backend.skills import SkillStore


class ChatDatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.temp.name) / "test.sqlite3")
        self.db.initialize()
        self.user = self.db.create_user("chat-user", "hash", "salt")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_chat_lifecycle(self) -> None:
        chat = self.db.create_chat("chat_1", int(self.user["id"]), "New chat", "agent-test")
        self.assertEqual(chat["title"], "New chat")
        self.db.append_chat_message("chat_1", "user", "hello")
        message = self.db.append_chat_message(
            "chat_1", "assistant", "hi", {"events": [{"kind": "mcp_connected"}], "usage": {"tokens": 1}}
        )
        self.assertEqual(message["meta"]["usage"]["tokens"], 1)
        items = self.db.list_chats(int(self.user["id"]))
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["message_count"], 2)
        messages = self.db.list_chat_messages("chat_1")
        self.assertEqual([message["role"] for message in messages], ["user", "assistant"])
        self.db.update_chat("chat_1", title="Renamed", agent_id="agent-other")
        updated = self.db.get_chat("chat_1")
        self.assertEqual(updated["title"], "Renamed")
        self.assertEqual(updated["agent_id"], "agent-other")
        self.db.clear_chat_messages("chat_1")
        self.assertEqual(self.db.list_chat_messages("chat_1"), [])
        self.db.delete_chat("chat_1")
        self.assertIsNone(self.db.get_chat("chat_1"))

    def test_chat_file_lifecycle(self) -> None:
        self.db.create_chat("chat_file", int(self.user["id"]), "Files", "agent-test")
        record = self.db.create_chat_file(
            "cf_1", "chat_file", int(self.user["id"]), "notes.txt", "C:/tmp/notes.txt", 5, "text/plain", "abc"
        )
        self.assertEqual(record["filename"], "notes.txt")
        self.assertEqual(len(self.db.list_chat_files("chat_file")), 1)
        self.assertIsNotNone(self.db.get_chat_file("cf_1"))
        self.db.delete_chat_file("cf_1")
        self.assertIsNone(self.db.get_chat_file("cf_1"))
        self.db.create_chat_file(
            "cf_2", "chat_file", int(self.user["id"]), "notes2.txt", "C:/tmp/notes2.txt", 5, "text/plain", "def"
        )
        self.db.delete_chat_files("chat_file")
        self.assertEqual(self.db.list_chat_files("chat_file"), [])


class ChatServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.config = BackendConfig.load(data_dir=self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _service(self, protocol: str) -> ChatService:
        provider = ProviderConfig(
            id="provider-test",
            name="Test Provider",
            protocol=protocol,
            base_url="https://example.test",
            model="test-model",
            api_key="test-key",
            context_window=8192,
            max_tokens=512,
            max_steps=2,
        )
        agent = AgentSpec(
            id="agent-test",
            name="Test Agent",
            kind="llm",
            provider_id=provider.id,
            provider_name=provider.name,
            protocol=provider.protocol,
            model=provider.model,
            base_url=provider.base_url,
            context_window=provider.context_window,
            max_tokens=provider.max_tokens,
            provider_available=True,
        )
        jobs = SimpleNamespace(
            config=self.config,
            providers=SimpleNamespace(get=lambda provider_id, include_key=True: provider),
            agents=SimpleNamespace(resolve_skills=lambda agent: [], resolve_mcps=lambda agent: []),
        )
        return ChatService(jobs), agent

    def test_openai_chat_loop(self) -> None:
        service, agent = self._service("openai")
        response = {"choices": [{"message": {"content": "OK"}}], "usage": {"total_tokens": 3}}
        with mock.patch("backend.chat._post_json", return_value=response):
            result = service.reply({}, agent, [{"role": "user", "content": "hello"}])
        self.assertEqual(result.text, "OK")
        self.assertEqual(result.protocol, "openai")
        self.assertEqual(result.usage["total_tokens"], 3)

    def test_anthropic_chat_loop(self) -> None:
        service, agent = self._service("anthropic")
        response = {"content": [{"type": "text", "text": "HI"}], "usage": {"input_tokens": 2}}
        with mock.patch("backend.chat._post_json", return_value=response):
            result = service.reply({}, agent, [{"role": "user", "content": "hello"}])
        self.assertEqual(result.text, "HI")
        self.assertEqual(result.protocol, "anthropic")
        self.assertEqual(result.usage["input_tokens"], 2)

    def test_chat_attachment_text_is_sent(self) -> None:
        service, agent = self._service("openai")
        attachment_path = Path(self.temp.name) / "notes.txt"
        attachment_path.write_text("attachment-secret-marker", encoding="utf-8")
        response = {"choices": [{"message": {"content": "OK"}}], "usage": {}}
        with mock.patch("backend.chat._post_json", return_value=response) as post:
            result = service.reply(
                {},
                agent,
                [{"role": "user", "content": "read this"}],
                attachments=[
                    {
                        "filename": "notes.txt",
                        "path": str(attachment_path),
                        "size": attachment_path.stat().st_size,
                        "mime": "text/plain",
                    }
                ],
            )
        self.assertEqual(result.text, "OK")
        payload = post.call_args.args[2]
        self.assertIn("attachment-secret-marker", str(payload["messages"]))

    def test_stop_cancels_before_next_tool_call(self) -> None:
        service, agent = self._service("openai")
        tool_response = {
            "choices": [
                {
                    "message": {
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "function": {"name": "apu_list_resources", "arguments": "{}"},
                            }
                        ],
                    }
                }
            ],
            "usage": {},
        }

        def post(*args, **kwargs):
            # Simulate the user pressing stop while the model call is in flight.
            self.assertTrue(service.request_cancel("chat_1"))
            return tool_response

        with mock.patch("backend.chat._post_json", side_effect=post):
            with self.assertRaises(ChatError):
                service.reply(
                    {"id": "chat_1", "user_id": 0},
                    agent,
                    [{"role": "user", "content": "hello"}],
                )
        self.assertFalse(service.is_active("chat_1"))
        self.assertFalse(service.request_cancel("chat_1"))

    def test_auto_protocol_order(self) -> None:
        provider = ProviderConfig(
            id="p",
            name="p",
            protocol="auto",
            base_url="https://example.test/anthropic",
            model="deepseek-chat",
            api_key="k",
        )
        self.assertEqual(ChatService._protocols(provider), ["anthropic", "openai"])
        provider.base_url = "https://example.test"
        provider.model = "claude-sonnet-5"
        self.assertEqual(ChatService._protocols(provider), ["anthropic", "openai"])
        provider.model = "deepseek-chat"
        self.assertEqual(ChatService._protocols(provider), ["openai", "anthropic"])


class ChatResourceToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = BackendConfig.load(data_dir=Path(self.temp.name) / "data")
        self.db = Database(self.config.data_dir / "backend.sqlite3")
        self.db.initialize()
        self.user = self.db.create_user("alice", "hash", "salt")
        self.uid = int(self.user["id"])
        self.providers = ProviderStore(self.config, self.db)
        self.provider = self.providers.create(
            {
                "id": "provider-test",
                "name": "Test",
                "protocol": "openai",
                "base_url": "https://example.test",
                "model": "test-model",
                "api_key": "test-key",
            }
        )
        self.skills = SkillStore(self.config, self.db)
        self.mcps = McpStore(self.config, self.db)
        self.agents = AgentStore(self.config, self.db, self.providers, self.skills, self.mcps)
        self.agents.ensure_provider_agent(self.provider)
        self.jobs = SimpleNamespace(
            config=self.config,
            database=self.db,
            providers=self.providers,
            skills=self.skills,
            mcps=self.mcps,
            agents=self.agents,
            refresh_engines=lambda: None,
        )
        self.service = ChatService(self.jobs)
        self.agent = self.agents.get(f"agent-{self.provider.id}")

    def _tool_call(self, name: str, arguments: dict) -> dict:
        return {
            "choices": [
                {
                    "message": {
                        "content": "",
                        "tool_calls": [
                            {"id": "call_1", "function": {"name": name, "arguments": json.dumps(arguments)}}
                        ],
                    }
                }
            ],
            "usage": {},
        }

    def _text(self, text: str) -> dict:
        return {"choices": [{"message": {"content": text}}], "usage": {}}

    def test_chat_tool_creates_personal_skill(self) -> None:
        responses = [
            self._tool_call("apu_create_skill", {"name": "chat-skill", "content": "# from chat"}),
            self._text("done"),
        ]
        with mock.patch("backend.chat._post_json", side_effect=responses):
            result = self.service.reply({"user_id": self.uid}, self.agent, [{"role": "user", "content": "add a skill"}])
        self.assertEqual(result.text, "done")
        rows = self.skills.list(visible_to=self.uid)
        created = next((item for item in rows if item["name"] == "chat-skill"), None)
        self.assertIsNotNone(created)
        self.assertEqual(created["owner_id"], self.uid)
        self.assertTrue(any(event["kind"] == "chat_tool_result" for event in result.events))

    def test_chat_tool_blocks_stdio_for_regular_user(self) -> None:
        responses = [
            self._tool_call(
                "apu_create_mcp",
                {"name": "bad-stdio", "transport": "stdio", "command": "echo hi"},
            ),
            self._text("blocked"),
        ]
        with mock.patch("backend.chat._post_json", side_effect=responses):
            result = self.service.reply({"user_id": self.uid}, self.agent, [{"role": "user", "content": "add mcp"}])
        self.assertEqual(result.text, "blocked")
        self.assertEqual(self.mcps.list(visible_to=self.uid), [])
        self.assertTrue(any(event["kind"] == "tool_error" for event in result.events))

    def test_chat_tool_lists_visible_resources(self) -> None:
        self.skills.create({"name": "shared-skill", "content": "# shared"})
        self.skills.create({"name": "alice-skill", "content": "# mine"}, owner_id=self.uid)
        responses = [
            self._tool_call("apu_list_resources", {}),
            self._text("listed"),
        ]
        with mock.patch("backend.chat._post_json", side_effect=responses):
            result = self.service.reply({"user_id": self.uid}, self.agent, [{"role": "user", "content": "list"}])
        event = next(item for item in result.events if item["kind"] == "chat_tool_result")
        payload = event["data"]["result"]
        if isinstance(payload, str):
            payload = json.loads(payload)
        names = {item["name"] for item in payload["skills"]} if isinstance(payload, dict) else set()
        self.assertIn("shared-skill", names)
        self.assertIn("alice-skill", names)

    def test_admin_chat_tool_creates_shared_resource(self) -> None:
        admin = self.db.create_user("admin2", "hash", "salt", "admin")
        responses = [
            self._tool_call("apu_create_skill", {"name": "shared-from-chat", "content": "# shared"}),
            self._text("done"),
        ]
        with mock.patch("backend.chat._post_json", side_effect=responses):
            self.service.reply({"user_id": int(admin["id"])}, self.agent, [{"role": "user", "content": "add"}])
        rows = self.db.list_skills()
        row = next((item for item in rows if item["name"] == "shared-from-chat"), None)
        self.assertIsNotNone(row)
        self.assertIsNone(row["owner_id"])

    def test_chat_backend_tools_read_and_create_task(self) -> None:
        self.db.create_upload("upload_1", self.uid, "target.apk", "/tmp/target.apk", 10, "abc")
        created: dict = {}

        def create_job(**kwargs):
            created.update(kwargs)
            return {"id": "job_1", "status": "queued", "stage": "queued", "engine": kwargs["engine"]}

        jobs = SimpleNamespace(
            database=self.db,
            providers=self.providers,
            skills=self.skills,
            mcps=self.mcps,
            agents=self.agents,
            engines={"agent-native": SimpleNamespace(agent=None, available=True)},
            engine_availability=lambda: {"agent-native": True},
            create_job=create_job,
            resolve_device=lambda: "serial-test",
            service=SimpleNamespace(),
        )
        toolbox = ChatToolbox(jobs, user_id=self.uid, owner_id=self.uid, is_admin=False, can_write=True)
        overview = toolbox.call("apu_backend_overview", {})
        self.assertEqual(overview["uploads"]["count"], 1)
        uploads = toolbox.call("apu_list_uploads", {})
        self.assertEqual(uploads["uploads"][0]["id"], "upload_1")
        task = toolbox.call(
            "apu_create_task",
            {
                "upload_id": "upload_1",
                "engine": "agent-native",
                "options": {"arm_device": True},
            },
        )
        self.assertEqual(task["id"], "job_1")
        self.assertEqual(created["user_id"], self.uid)
        self.assertEqual(created["upload_id"], "upload_1")
        self.assertTrue(created["options"]["install"])
        self.assertTrue(created["options"]["jadx"])
        self.assertTrue(created["options"]["cleanup"])
        self.assertTrue(created["options"]["arm_device"])
        self.assertIsNone(created["serial"])
        with self.assertRaises(ChatError):
            toolbox.call("apu_register_device", {"serial": "127.0.0.1:5556"})

    def test_admin_chat_tool_registers_device(self) -> None:
        admin = self.db.create_user("admin3", "hash", "salt", "admin")
        jobs = SimpleNamespace(
            database=self.db,
            providers=self.providers,
            skills=self.skills,
            mcps=self.mcps,
            agents=self.agents,
            service=SimpleNamespace(),
        )
        toolbox = ChatToolbox(
            jobs, user_id=int(admin["id"]), owner_id=None, is_admin=True, can_write=True
        )
        result = toolbox.call(
            "apu_register_device", {"serial": "redroid-lab", "name": "Lab", "kind": "redroid"}
        )
        self.assertEqual(result["registered"], "redroid-lab")
        row = self.db.get_device("redroid-lab")
        self.assertIsNotNone(row)
        self.assertEqual(row["source"], "manual")
        self.assertEqual(row["name"], "Lab")
        devices = toolbox.call("apu_list_devices", {})["devices"]
        self.assertTrue(any(item["serial"] == "redroid-lab" for item in devices))


class ChatJobOptionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = BackendConfig.load(data_dir=Path(self.temp.name) / "data")
        self.db = Database(self.config.db_path)
        self.db.initialize()
        self.user = self.db.create_user("opts-user", "hash", "salt")
        self.uid = int(self.user["id"])
        self.db.create_upload("upload_1", self.uid, "target.apk", "/tmp/target.apk", 4, "0" * 64)
        self.created: dict[str, Any] = {}
        self.retried: dict[str, Any] = {}
        self.jobs = SimpleNamespace(
            database=self.db,
            agents=SimpleNamespace(canonical_engine=lambda engine: engine or "agent-native"),
            engines={"agent-native": SimpleNamespace(agent=None, available=True)},
            default_engine=lambda visible_to=None: "agent-native",
            create_job=self._create_job,
            retry_job=self._retry_job,
        )
        self.toolbox = ChatToolbox(
            self.jobs, user_id=self.uid, owner_id=self.uid, is_admin=False, can_write=True
        )

    def _create_job(self, **kwargs: Any) -> dict[str, Any]:
        self.created.update(kwargs)
        return {"id": "job_chat_1", "status": "queued", "stage": "queued", "engine": kwargs["engine"]}

    def _retry_job(self, job_id: str, user_id: int, is_admin: bool = False) -> dict[str, Any]:
        self.retried = {"job_id": job_id}
        return {"id": "job_chat_retry", "status": "queued", "stage": "queued", "engine": "agent-native"}

    def _make_job(self, job_id: str, status: str) -> None:
        self.db.create_job(job_id, self.uid, "upload_1", "agent-native", None, {}, f"run_{job_id}")
        self.db.update_job(job_id, status=status)

    def test_chat_schema_uses_shared_options(self) -> None:
        tools = {tool["function"]["name"]: tool["function"] for tool in self.toolbox.openai_tools}
        options = tools["apu_create_task"]["parameters"]["properties"]["options"]
        self.assertFalse(options["additionalProperties"])
        properties = options["properties"]
        for name in (
            "arm_device",
            "install",
            "freeze_timeout_ms",
            "frida_server_path",
            "dump_region_max",
            "jadx_timeout_s",
            "timeout_s",
        ):
            self.assertIn(name, properties)
        self.assertNotIn("_auto_device", properties)
        self.assertNotIn("_arm_runtime", properties)

    def test_chat_forwards_normalized_options(self) -> None:
        self.toolbox.call(
            "apu_create_task",
            {
                "upload_id": "upload_1",
                "engine": "agent-native",
                "options": {
                    "arm_device": True,
                    "freeze_timeout_ms": 1000,
                    "dump_region_max": 2048,
                    "frida_server_path": "/opt/frida",
                },
            },
        )
        options = self.created["options"]
        self.assertTrue(options["install"])
        self.assertTrue(options["jadx"])
        self.assertTrue(options["cleanup"])
        self.assertTrue(options["arm_device"])
        self.assertEqual(options["freeze_timeout_ms"], 1000)
        self.assertEqual(options["max_region_bytes"], 2048)
        self.assertEqual(options["_frida_server_path"], "/opt/frida")

    def test_chat_rejects_invalid_options(self) -> None:
        with self.assertRaises(ChatError):
            self.toolbox.call(
                "apu_create_task",
                {
                    "upload_id": "upload_1",
                    "engine": "agent-native",
                    "options": {"_auto_device": True},
                },
            )
        self.assertEqual(self.created, {})

    def test_chat_retry_only_for_finished_unsuccessful_jobs(self) -> None:
        for status in ("queued", "running", "succeeded"):
            self._make_job(f"job_{status}", status)
            with self.assertRaises(ChatError):
                self.toolbox.call("apu_retry_job", {"job_id": f"job_{status}"})
        self._make_job("job_failed", "failed")
        result = self.toolbox.call("apu_retry_job", {"job_id": "job_failed"})
        self.assertEqual(result["id"], "job_chat_retry")
        self.assertEqual(self.retried, {"job_id": "job_failed"})
        actions = [row["action"] for row in self.db.list_audit(limit=50)[0]]
        self.assertIn("job.retry", actions)


class StorageHelperTests(unittest.TestCase):
    def test_path_bytes_and_age(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            file = root / "a.bin"
            file.write_bytes(b"12345")
            (root / "sub").mkdir()
            (root / "sub" / "b.bin").write_bytes(b"123")
            self.assertEqual(_path_bytes(file), 5)
            self.assertEqual(_path_bytes(root), 8)
            self.assertEqual(_upload_bytes({"path": str(file)}), 5)
            self.assertTrue(_older_than("2000-01-01T00:00:00+00:00", None))
            self.assertTrue(_older_than("2999-01-01T00:00:00+00:00", None))
            from datetime import datetime, timezone
            cutoff = datetime(2020, 1, 1, tzinfo=timezone.utc)
            self.assertTrue(_older_than("2019-01-01T00:00:00+00:00", cutoff))
            self.assertFalse(_older_than("2021-01-01T00:00:00+00:00", cutoff))

    def test_remove_job_files_stays_in_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            jobs = root / "jobs"
            runs = root / "runs"
            (jobs / "job_1").mkdir(parents=True)
            (runs / "run_1").mkdir(parents=True)
            outside = root / "outside"
            outside.mkdir()
            manager = object.__new__(JobManager)
            manager.config = SimpleNamespace(jobs_dir=jobs, runs_dir=runs)
            manager._remove_job_files({"id": "job_1", "run_id": "run_1"})
            self.assertFalse((jobs / "job_1").exists())
            self.assertFalse((runs / "run_1").exists())
            manager._remove_job_files({"id": "../outside", "run_id": "../outside"})
            self.assertTrue(outside.exists())


if __name__ == "__main__":
    unittest.main()
