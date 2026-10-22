from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from backend.agents import AgentStore
from backend.config import BackendConfig
from backend.db import Database
from backend.engines import EngineResult
from backend.jobs import JobManager
from backend.mcp import McpStore
from backend.providers import ProviderStore
from backend.server import BackendApp
from backend.skills import SkillStore


class FakeDevice:
    def __init__(self, serial: str, state: str = "device"):
        self.serial = serial
        self.state = state

    def to_dict(self) -> dict:
        return {"serial": self.serial, "state": self.state, "attrs": {}}


class FakeAdb:
    def __init__(self, online: list[str]):
        self.online = set(online)

    def devices(self):
        return [FakeDevice(serial) for serial in sorted(self.online)]

    def run(self, args, timeout=None):
        if args[:1] == ["connect"]:
            self.online.add(args[1])
            return SimpleNamespace(ok=True, stdout="connected", stderr="")
        return SimpleNamespace(ok=False, stdout="", stderr="")


def job_manager_for(adb: FakeAdb, db: Database, preferred: str = "127.0.0.1:5555"):
    manager = object.__new__(JobManager)
    manager.config = SimpleNamespace(serial=preferred)
    manager.database = db
    manager.service = SimpleNamespace(adb=adb)
    return manager


class OwnershipTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = BackendConfig.load(data_dir=Path(self.temp.name) / "data")
        self.db = Database(self.config.data_dir / "backend.sqlite3")
        self.db.initialize()
        self.user_a = self.db.create_user("alice", "hash", "salt")
        self.user_b = self.db.create_user("bob", "hash", "salt")
        self.a = int(self.user_a["id"])
        self.b = int(self.user_b["id"])
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

    def _skill(self, name: str, owner: int | None) -> dict:
        return self.skills.create({"name": name, "content": f"# {name}"}, owner_id=owner)

    def _mcp(self, name: str, owner: int | None):
        return self.mcps.create(
            {"name": name, "transport": "http", "url": "https://mcp.example.test"},
            owner_id=owner,
        )

    def _agent(self, name: str, owner: int | None, skill_ids: list[str], mcp_ids: list[str] | None = None):
        return self.agents.create(
            {
                "name": name,
                "provider_id": self.provider.id,
                "skill_ids": skill_ids,
                "mcp_ids": mcp_ids or [],
            },
            owner_id=owner,
        )

    def test_visible_catalogs_are_shared_plus_own(self) -> None:
        shared = self._skill("shared", None)
        alice = self._skill("alice", self.a)
        bob = self._skill("bob", self.b)
        shared_mcp = self._mcp("shared-mcp", None)
        alice_mcp = self._mcp("alice-mcp", self.a)
        bob_mcp = self._mcp("bob-mcp", self.b)
        shared_agent = self._agent("shared-agent", None, [shared["id"]])
        alice_agent = self._agent("alice-agent", self.a, [alice["id"]])
        bob_agent = self._agent("bob-agent", self.b, [bob["id"]])

        names = {item["id"] for item in self.skills.list(visible_to=self.a)}
        self.assertIn(shared["id"], names)
        self.assertIn(alice["id"], names)
        self.assertNotIn(bob["id"], names)

        mcp_names = {item.id for item in self.mcps.list(visible_to=self.a)}
        self.assertIn(shared_mcp.id, mcp_names)
        self.assertIn(alice_mcp.id, mcp_names)
        self.assertNotIn(bob_mcp.id, mcp_names)

        agent_names = {item.id for item in self.agents.list(visible_to=self.a)}
        self.assertIn(shared_agent.id, agent_names)
        self.assertIn(alice_agent.id, agent_names)
        self.assertNotIn(bob_agent.id, agent_names)

        # Admins (no filter) still see everything.
        self.assertEqual(len({item.id for item in self.agents.list()}), 3)

    def test_agent_cannot_reference_another_users_private_resource(self) -> None:
        bob_skill = self._skill("bob-private", self.b)
        with self.assertRaises(ValueError):
            self._agent("alice-bad", self.a, [bob_skill["id"]])
        # Shared resources remain available to every user.
        shared = self._skill("shared", None)
        agent = self._agent("alice-ok", self.a, [shared["id"]])
        self.assertEqual(agent.owner_id, self.a)

    def test_shared_agent_rejects_private_resource(self) -> None:
        alice_skill = self._skill("alice-private", self.a)
        with self.assertRaises(ValueError):
            self._agent("shared-bad", None, [alice_skill["id"]])

    def test_device_registry_keeps_manual_names(self) -> None:
        record = self.db.upsert_device(
            "127.0.0.1:5556", name="redroid11_x86_64", kind="redroid", address="127.0.0.1:5556", seen=True
        )
        self.assertEqual(record["source"], "auto")
        self.assertEqual(record["name"], "redroid11_x86_64")
        self.assertIsNotNone(record["last_seen_at"])
        self.db.upsert_device(
            "127.0.0.1:5556", name="Lab device", kind="redroid", source="manual"
        )
        self.db.update_device("127.0.0.1:5556", source="manual")
        self.db.upsert_device("127.0.0.1:5556", name="Auto overwrite", source="auto", seen=True)
        row = self.db.get_device("127.0.0.1:5556")
        self.assertEqual(row["name"], "Lab device")
        self.assertEqual(row["source"], "manual")
        self.db.update_device("127.0.0.1:5556", notes="offline spare")
        items = self.db.list_devices()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["notes"], "offline spare")
        self.db.delete_device("127.0.0.1:5556")
        self.assertIsNone(self.db.get_device("127.0.0.1:5556"))

    def test_default_engine_prefers_available_model_agent(self) -> None:
        manager = object.__new__(JobManager)
        manager.engines = {
            "agent-native": SimpleNamespace(
                agent=SimpleNamespace(kind="native", provider_id=None), available=True
            ),
            "agent-openai-generic": SimpleNamespace(
                agent=SimpleNamespace(kind="llm", provider_id="openai-generic"), available=True
            ),
            "agent-deepseek-openai": SimpleNamespace(
                agent=SimpleNamespace(kind="llm", provider_id="deepseek-openai"), available=True
            ),
            "agent-anthropic-claude": SimpleNamespace(
                agent=SimpleNamespace(kind="llm", provider_id="anthropic-claude"), available=False
            ),
        }
        self.assertEqual(manager.default_engine(), "agent-deepseek-openai")
        manager.engines["agent-deepseek-openai"].available = False
        self.assertEqual(manager.default_engine(), "agent-openai-generic")
        manager.engines["agent-openai-generic"].available = False
        self.assertEqual(manager.default_engine(), "agent-native")

    def test_auto_device_resolution(self) -> None:
        manager = job_manager_for(FakeAdb(["emulator-5554"]), self.db)
        self.assertEqual(manager.resolve_device(), "emulator-5554")
        self.assertEqual(manager.resolve_device("explicit-1"), "explicit-1")
        manager = job_manager_for(FakeAdb(["127.0.0.1:5555", "emulator-5554"]), self.db)
        self.assertEqual(manager.resolve_device(), "127.0.0.1:5555")
        # No online device: connect the configured default serial.
        manager = job_manager_for(FakeAdb([]), self.db)
        self.assertEqual(manager.resolve_device(), "127.0.0.1:5555")
        # Nothing configured or connectable returns None.
        self.db.delete_device("127.0.0.1:5555")
        manager = job_manager_for(FakeAdb([]), self.db, preferred="")
        self.assertIsNone(manager.resolve_device())

    def test_duplicate_adb_transports_share_one_serial(self) -> None:
        manager = job_manager_for(FakeAdb(["127.0.0.1:5555", "emulator-5554"]), self.db)
        # A redroid exposed through both emulator-5554 and 127.0.0.1:5555
        # must schedule/lock as a single physical device.
        manager._device_identity = lambda serial: "pidns:same"  # type: ignore[method-assign]
        self.assertEqual(manager._online_serials(), ["127.0.0.1:5555"])
        self.assertEqual(manager.canonical_serial("emulator-5554"), "127.0.0.1:5555")
        self.assertEqual(manager.canonical_serial("127.0.0.1:5555"), "127.0.0.1:5555")

    def test_distinct_containers_are_not_deduped(self) -> None:
        manager = job_manager_for(FakeAdb(["127.0.0.1:5555", "127.0.0.1:5557"]), self.db)
        identities = {"127.0.0.1:5555": "pidns:a", "127.0.0.1:5557": "pidns:b"}
        manager._device_identity = lambda serial: identities[serial]  # type: ignore[method-assign]
        self.assertEqual(manager._online_serials(), ["127.0.0.1:5555", "127.0.0.1:5557"])

    def test_hidden_transport_blocks_duplicate_for_jobs(self) -> None:
        manager = job_manager_for(FakeAdb(["127.0.0.1:5555", "emulator-5554"]), self.db)
        manager._device_identity = lambda serial: "pidns:same"  # type: ignore[method-assign]
        self.db.upsert_device("127.0.0.1:5555", name="x", address="127.0.0.1:5555")
        self.db.hide_device("127.0.0.1:5555")
        self.db.upsert_device("emulator-5554", name="e", address="emulator-5554")
        self.assertEqual(manager._online_serials(), [])

    def test_device_list_hides_duplicate_of_hidden_transport(self) -> None:
        app = BackendApp(self.config)
        app.database = self.db
        app.jobs = SimpleNamespace(
            service=SimpleNamespace(adb=FakeAdb(["emulator-5554", "127.0.0.1:5555"])),
            device_identity=lambda serial: "pidns:same",
            dedupe_serials=lambda serials: ["127.0.0.1:5555"],
        )
        self.db.upsert_device("127.0.0.1:5555", name="x", address="127.0.0.1:5555")
        self.db.hide_device("127.0.0.1:5555")
        self.db.upsert_device("emulator-5554", name="e", address="emulator-5554")
        self.assertEqual({item["serial"] for item in app.device_list()}, set())
        scanned = {item["serial"] for item in app.device_list(include_hidden=True)}
        self.assertIn("127.0.0.1:5555", scanned)

    def test_device_list_hides_duplicate_transport(self) -> None:
        app = BackendApp(self.config)
        app.database = self.db
        app.jobs = SimpleNamespace(
            service=SimpleNamespace(adb=FakeAdb(["emulator-5554", "127.0.0.1:5555"])),
            dedupe_serials=lambda serials: ["127.0.0.1:5555"],
        )
        visible = {item["serial"] for item in app.device_list()}
        self.assertEqual(visible, {"127.0.0.1:5555"})

    def test_device_scan_can_include_hidden_for_explicit_restore(self) -> None:
        app = BackendApp(self.config)
        app.database = self.db
        app.jobs = SimpleNamespace(service=SimpleNamespace(adb=FakeAdb(["emulator-5554", "127.0.0.1:5555"])))
        visible = {item["serial"] for item in app.device_list()}
        self.assertEqual(visible, {"emulator-5554", "127.0.0.1:5555"})
        self.db.hide_device("127.0.0.1:5555")
        self.assertNotIn("127.0.0.1:5555", {item["serial"] for item in app.device_list()})
        scanned = {item["serial"] for item in app.device_list(include_hidden=True)}
        self.assertIn("127.0.0.1:5555", scanned)
        # Explicit add unhides it, so the next normal refresh shows it again.
        self.db.update_device("127.0.0.1:5555", hidden=0)
        self.assertIn("127.0.0.1:5555", {item["serial"] for item in app.device_list()})

    def test_default_engine_skips_another_users_private_agent(self) -> None:
        manager = object.__new__(JobManager)
        manager.engines = {
            "agent-native": SimpleNamespace(
                agent=SimpleNamespace(kind="native", provider_id=None, owner_id=None), available=True
            ),
            "agent-alice": SimpleNamespace(
                agent=SimpleNamespace(
                    kind="llm", provider_id="deepseek-openai", owner_id=self.a
                ),
                available=True,
            ),
            "agent-shared": SimpleNamespace(
                agent=SimpleNamespace(kind="llm", provider_id="openai-generic", owner_id=None),
                available=True,
            ),
        }
        self.assertEqual(manager.default_engine(visible_to=self.b), "agent-shared")
        self.assertEqual(manager.default_engine(visible_to=self.a), "agent-alice")

    def test_outcome_guard_downgrades_packed_static_success(self) -> None:
        from tests.fixtures import build_dex, build_valid_dex

        manager = object.__new__(JobManager)
        run_dir = Path(self.temp.name) / "run_guard"
        run_dir.mkdir()
        fixed = run_dir / "dexdump" / "fixed"
        fixed.mkdir(parents=True)
        state = {
            "package": "com.example",
            "artifacts": {
                "inspection": {
                    "packing": {"primary": "360", "display": "360 Jiagu", "packed": True},
                    "dex_entries": [{"name": "classes.dex", "packed_stub": True}],
                },
                "attempts": [],
            },
        }
        (run_dir / "run.json").write_text(__import__("json").dumps(state), encoding="utf-8")
        events = []
        result = EngineResult("success", run_id="run_guard")
        guarded = manager._guard_outcome(
            result, SimpleNamespace(run_dir=run_dir), lambda *args, **kwargs: events.append((args, kwargs))
        )
        self.assertEqual(guarded.outcome, "partial")
        self.assertEqual(guarded.error["code"], "packed_static_only")
        self.assertTrue(events)

        # A dynamic dump attempt alone is not enough: the produced DEX must be
        # complete and contain target-package classes.
        state["artifacts"]["attempts"] = [{"method": "memory_dd", "status": "succeeded"}]
        (run_dir / "run.json").write_text(__import__("json").dumps(state), encoding="utf-8")
        (fixed / "classes.dex").write_bytes(build_dex(class_defs_size=1))
        guarded = manager._guard_outcome(
            EngineResult("success", run_id="run_guard"),
            SimpleNamespace(run_dir=run_dir),
            lambda *args, **kwargs: None,
        )
        self.assertEqual(guarded.outcome, "partial")
        self.assertIn(guarded.error["code"], ("stub_only", "unverified"))

        (fixed / "classes.dex").write_bytes(build_valid_dex("com.example"))
        guarded = manager._guard_outcome(
            EngineResult("success", run_id="run_guard"),
            SimpleNamespace(run_dir=run_dir),
            lambda *args, **kwargs: None,
        )
        self.assertEqual(guarded.outcome, "success")

    def test_auto_device_port_skips_registered_and_containers(self) -> None:
        manager = job_manager_for(FakeAdb([]), self.db, preferred="")
        manager.config.device_port_start = 5557
        manager.config.device_port_end = 5559
        self.db.upsert_device("127.0.0.1:5557", name="used", kind="redroid")
        manager._docker = lambda args, timeout=60: SimpleNamespace(
            returncode=0, stdout="apu-redroid-5558\n", stderr=""
        )
        self.assertEqual(manager._next_device_port(), 5559)

    def test_auto_device_creates_redroid_when_none_online(self) -> None:
        manager = job_manager_for(FakeAdb([]), self.db, preferred="")
        manager.config.device_auto_create = True
        manager.config.device_max_containers = 2
        manager.config.device_image = "redroid:test"
        manager.config.device_port_start = 5557
        manager.config.device_port_end = 5559
        manager.config.device_create_timeout_s = 30
        calls: list[list[str]] = []

        def fake_docker(args, timeout=60):
            calls.append(args)
            if args[:1] == ["ps"]:
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            return SimpleNamespace(returncode=0, stdout="container-id", stderr="")

        manager._docker = fake_docker
        manager._wait_for_device = lambda serial, timeout_s: manager.service.adb.online.add(serial) or True
        with mock.patch.dict(os.environ, {"APU_WEB_DEVICE_START_CMD": ""}):
            serial = manager.resolve_device()
        self.assertEqual(serial, "127.0.0.1:5557")
        run = next(args for args in calls if args and args[0] == "run")
        self.assertIn("apu-redroid-5557", run)
        self.assertIn("127.0.0.1:5557:5555", run)
        record = self.db.get_device("127.0.0.1:5557")
        self.assertIsNotNone(record)
        self.assertEqual(record["kind"], "redroid")

    def test_auto_device_lists_x86_before_arm(self) -> None:
        self.db.upsert_device("127.0.0.1:5557", name="arm", kind="redroid", seen=True, arch="arm64")
        self.db.upsert_device("127.0.0.1:5555", name="x86", kind="redroid", seen=True, arch="x86_64")
        manager = job_manager_for(FakeAdb(["127.0.0.1:5557", "127.0.0.1:5555"]), self.db, preferred="")
        self.assertEqual(manager._online_serials(), ["127.0.0.1:5555", "127.0.0.1:5557"])

    def test_arm_runtime_options_apply_slow_budget(self) -> None:
        manager = job_manager_for(FakeAdb([]), self.db, preferred="")
        manager.config.frida_server_arm64 = "/opt/apu-web/bin/frida-server-arm64"
        options = manager._arm_runtime_options({"install": True})
        self.assertTrue(options["_arm_runtime"])
        self.assertEqual(options["_device_arch"], "arm64")
        self.assertEqual(options["freeze_timeout_ms"], 180_000)
        self.assertEqual(options["frida_timeout_ms"], 180_000)
        self.assertEqual(options["timeout_s"], 7200)
        self.assertEqual(options["_frida_server_path"], "/opt/apu-web/bin/frida-server-arm64")
        self.assertTrue(options["install"])
        # Explicit user budgets win.
        pinned = manager._arm_runtime_options({"freeze_timeout_ms": 5_000})
        self.assertEqual(pinned["freeze_timeout_ms"], 5_000)

    def test_online_arm_serial_selection(self) -> None:
        self.db.upsert_device("127.0.0.1:5557", name="arm", kind="redroid", seen=True, arch="arm64")
        self.db.upsert_device("127.0.0.1:5555", name="x86", kind="redroid", seen=True, arch="x86_64")
        manager = job_manager_for(FakeAdb(["127.0.0.1:5555", "127.0.0.1:5557"]), self.db, preferred="")
        self.assertEqual(manager._online_arm_serial(), "127.0.0.1:5557")

    def test_arm_container_is_created_with_platform_and_arch(self) -> None:
        manager = job_manager_for(FakeAdb([]), self.db, preferred="")
        manager.config = SimpleNamespace(
            serial="",
            device_auto_create=True,
            device_arm_enabled=True,
            device_arm_max_containers=1,
            device_arm_image="redroid:arm-test",
            device_arm_platform="linux/arm64",
            device_arm_create_timeout_s=30,
            device_port_start=5557,
            device_port_end=5559,
        )
        calls: list[list[str]] = []

        def fake_docker(args, timeout=60):
            calls.append(args)
            if args[:1] == ["ps"]:
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            return SimpleNamespace(returncode=0, stdout="container-id", stderr="")

        manager._docker = fake_docker
        manager._wait_for_device = lambda serial, timeout_s: manager.service.adb.online.add(serial) or True
        serial = manager._create_redroid("arm64")
        self.assertEqual(serial, "127.0.0.1:5557")
        run = next(args for args in calls if args and args[0] == "run")
        self.assertIn("--platform", run)
        self.assertIn("linux/arm64", run)
        self.assertIn("redroid:arm-test", run)
        self.assertIn("apu-redroid-arm-5557", run)
        record = self.db.get_device("127.0.0.1:5557")
        self.assertEqual(record["arch"], "arm64")
        self.assertEqual(record["kind"], "redroid")

    def test_arm_fallback_reason_only_for_auto_x86_failures(self) -> None:
        manager = job_manager_for(FakeAdb(["127.0.0.1:5555"]), self.db, preferred="")
        manager.config.device_arm_enabled = True
        manager.config.device_arm_fallback = True
        self.db.upsert_device("127.0.0.1:5555", name="x86", kind="redroid", seen=True, arch="x86_64")
        run_dir = Path(self.temp.name) / "run_fallback"
        run_dir.mkdir()
        (run_dir / "run.json").write_text(
            json.dumps(
                {
                    "artifacts": {
                        "inspection": {
                            "packing": {"primary": "360", "display": "360 Jiagu", "packed": True},
                            "dex_entries": [{"name": "classes.dex", "packed_stub": True}],
                        },
                        "attempts": [],
                    }
                }
            ),
            encoding="utf-8",
        )
        ctx = SimpleNamespace(
            run_dir=run_dir,
            serial="127.0.0.1:5555",
            cancel=threading.Event(),
            options={"_auto_device": True},
        )
        result = EngineResult(
            "partial",
            run_id="run_fallback",
            error={"code": "packed_static_only", "message": "shell loader only"},
        )
        self.assertEqual(manager._arm_fallback_reason(result, ctx, True), "packed_static_only")
        self.assertEqual(manager._arm_fallback_reason(result, ctx, False), "")
        ctx.serial = "127.0.0.1:5557"
        self.db.upsert_device("127.0.0.1:5557", name="arm", kind="redroid", seen=True, arch="arm64")
        self.assertEqual(manager._arm_fallback_reason(result, ctx, True), "")
        ctx.serial = "127.0.0.1:5555"
        result.error = {"code": "configuration_error", "message": "missing tool"}
        self.assertEqual(manager._arm_fallback_reason(result, ctx, True), "")
        result.outcome = "success"
        self.assertEqual(manager._arm_fallback_reason(result, ctx, True), "")

    def test_hidden_device_is_not_re_registered_by_discovery(self) -> None:
        self.db.upsert_device("127.0.0.1:5556", name="redroid", kind="redroid", seen=True)
        self.db.hide_device("127.0.0.1:5556")
        self.assertNotIn("127.0.0.1:5556", {item["serial"] for item in self.db.list_devices()})
        self.assertIn(
            "127.0.0.1:5556",
            {item["serial"] for item in self.db.list_devices(include_hidden=True)},
        )
        # Auto-discovery keeps the row hidden instead of resurrecting it.
        self.db.upsert_device("127.0.0.1:5556", name="redroid", kind="redroid", seen=True)
        self.assertNotIn("127.0.0.1:5556", {item["serial"] for item in self.db.list_devices()})
        self.db.update_device("127.0.0.1:5556", hidden=0)
        self.assertIn("127.0.0.1:5556", {item["serial"] for item in self.db.list_devices()})

    def test_deleting_user_cascades_personal_resources(self) -> None:
        skill = self._skill("alice", self.a)
        self._mcp("alice-mcp", self.a)
        self._agent("alice-agent", self.a, [skill["id"]])
        self.db.delete_user(self.a)
        self.assertIsNone(self.db.get_skill(skill["id"]))
        self.assertIsNone(self.db.get_mcp_server("alice-mcp"))
        self.assertIsNone(self.db.get_agent("alice-agent"))
        # Shared resources survive.
        shared = self._skill("shared", None)
        self.db.delete_user(self.b)
        self.assertIsNotNone(self.db.get_skill(shared["id"]))


if __name__ == "__main__":
    unittest.main()
