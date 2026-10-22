from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from backend.chat import _system_text as chat_system_text
from backend.config import SKILL_PATH
from backend.engines import LLMEngineBase
from backend.prompts import system_prompt
from backend.skill_content import read_skill_bundle


class SkillBundleTests(unittest.TestCase):
    def test_default_skill_events_report_the_loaded_ten_references(self):
        events = []
        provider = SimpleNamespace(id="test", name="test", protocol="openai", model="test", base_url="", context_window=65536, max_tokens=4000, max_steps=20)
        engine = LLMEngineBase(None, provider=provider)
        ctx = SimpleNamespace(emit=lambda kind, message, data: events.append((kind, data)))
        engine._emit_config(ctx, provider, SimpleNamespace(info=[]))
        self.assertEqual(len(events[0][1]["skills"][0]["references"]), 10)
        self.assertEqual(len(events[1][1]["references"]), 10)

    def test_all_ten_complete_references_reach_job_and_chat_models(self):
        content, references = read_skill_bundle(SKILL_PATH)
        self.assertEqual(len(references), 10)
        skill = {"id": "unpack-android-apk", "content": content, "references": references}
        provider = SimpleNamespace(context_window=65536)
        engine = LLMEngineBase(None, provider=provider, skills=[skill])
        job = engine._system_text(provider)
        chat = chat_system_text(SimpleNamespace(system_prompt="", mcps=[]), [skill], provider)
        for name in references:
            reference = (SKILL_PATH.parent / name).read_text(encoding="utf-8").strip()
            self.assertIn(reference, job, name)
            self.assertIn(reference, chat, name)
        self.assertGreater(len(job), 30000)

    def test_missing_reference_stops_loading_instead_of_silently_reducing_knowledge(self):
        with TemporaryDirectory() as folder:
            main = Path(folder) / "unpack-android-apk" / "SKILL.md"
            main.parent.mkdir()
            main.write_text("# Skill", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "missing required APK skill references"):
                read_skill_bundle(main)

    def test_small_context_budget_reports_error_instead_of_cutting_reference_tail(self):
        content, _ = read_skill_bundle(SKILL_PATH)
        with self.assertRaisesRegex(ValueError, "complete skill context exceeds"):
            system_prompt([{"content": content}], max_chars=30000)

    def test_sample_identifiers_are_redacted_but_detection_signatures_remain(self):
        content, references = read_skill_bundle(SKILL_PATH)
        combined = "\n".join((SKILL_PATH.parent / name).read_text(encoding="utf-8") for name in references)
        for identifier in ("ceair", "yy.apk", "S365", "e.apk", "dishi.apk", "190.apk", "zybx", "sksx", "base.apk", "huiyuan", "11.apk", "中免日上", "com.beikatech", "com.cube.messager", "nniemoh.nipiiz.moc"):
            self.assertNotIn(identifier, combined)
        self.assertIn("libijm-emulator.so", content)
        self.assertIn("s.h.e.l.l.S", content)
        self.assertIn("com.secneo.apkwrapper.AP", content)


if __name__ == "__main__":
    unittest.main()
