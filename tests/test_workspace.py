from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from apk_unpack.domain.errors import AnalysisError
from apk_unpack.domain.evidence import create_evidence
from apk_unpack.domain.workspace import RunWorkspace


class WorkspaceTests(unittest.TestCase):
    def test_evidence_ledger_dedupes_and_detects_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = RunWorkspace.create(Path(tmp))
            evidence = create_evidence(
                operation="inspect_apk",
                normalized_result={"package": "com.example", "packed": True},
                subject={"format": "apk", "sha256": "a" * 64, "local_path": "x.apk"},
            )
            self.assertEqual(run.append_evidence(evidence), "added")
            self.assertEqual(run.append_evidence(evidence), "duplicate")
            conflicting = dict(evidence)
            conflicting["normalized_result"] = {"package": "com.example", "packed": False}
            with self.assertRaises(AnalysisError) as context:
                run.append_evidence(conflicting)
            self.assertEqual(context.exception.code, "integrity_mismatch")
            records, total = run.read_evidence()
            self.assertEqual(total, 1)
            self.assertEqual(records[0]["evidence_id"], evidence["evidence_id"])

    def test_evidence_identity_ignores_display_path(self) -> None:
        one = create_evidence(
            operation="inspect_apk",
            normalized_result={"a": 1},
            subject={"format": "apk", "sha256": "a" * 64, "name": "one.apk", "local_path": "C:/one.apk"},
        )
        two = create_evidence(
            operation="inspect_apk",
            normalized_result={"a": 1},
            subject={"format": "apk", "sha256": "a" * 64, "name": "two.apk", "local_path": "D:/two.apk"},
        )
        self.assertEqual(one["evidence_id"], two["evidence_id"])

    def test_mutations_and_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = RunWorkspace.create(Path(tmp), target={"path": "x.apk"})
            mutation = run.add_mutation(
                {
                    "kind": "adb_forward",
                    "target": "tcp:27042",
                    "detail": {"local_port": 27042},
                    "restore_command": ["adb", "forward", "--remove", "tcp:27042"],
                }
            )
            self.assertTrue(mutation["mutation_id"])
            self.assertEqual(len(run.load_mutations()), 1)
            run.update_mutation(mutation["mutation_id"], state="restored")
            self.assertEqual(run.load_mutations()[0]["state"], "restored")
            run.update_run(stage="inspected", evidence_ids=["ev_a"])
            state = run.load_run()
            self.assertEqual(state["stage"], "inspected")
            self.assertIn("ev_a", state["evidence_ids"])

    def test_lock_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = RunWorkspace.create(Path(tmp))
            with run.lock():
                with self.assertRaises(AnalysisError) as context:
                    with run.lock(timeout=0):
                        pass
                self.assertEqual(context.exception.code, "conflict")


if __name__ == "__main__":
    unittest.main()
