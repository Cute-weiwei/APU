from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .errors import AnalysisError, fail
from .jsonutil import canonical_json

RUN_ID_RE = re.compile(r"^run_[A-Za-z0-9_]+$")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_run_id() -> str:
    return "run_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + secrets.token_hex(4)


class RunWorkspace:
    """A single investigation run: state, evidence ledger, events, mutations."""

    def __init__(self, root: Path):
        self.root = Path(root)

    # ------------------------------------------------------------------ create / load
    @classmethod
    def create(
        cls,
        runs_dir: Path,
        *,
        run_id: str | None = None,
        target: dict[str, Any] | None = None,
        device: dict[str, Any] | None = None,
    ) -> "RunWorkspace":
        runs_dir = Path(runs_dir)
        runs_dir.mkdir(parents=True, exist_ok=True)
        run_id = run_id or new_run_id()
        if not RUN_ID_RE.match(run_id):
            raise fail("invalid_input", f"invalid run id: {run_id}")
        root = runs_dir / run_id
        if root.exists():
            raise fail("conflict", f"run already exists: {root}")
        workspace = cls(root)
        workspace.ensure_dirs()
        state = {
            "schema_version": 1,
            "run_id": run_id,
            "created_at": utc_now(),
            "updated_at": utc_now(),
            "stage": "created",
            "target": target or {},
            "device": device or {},
            "package": None,
            "strategy": None,
            "attempts": [],
            "artifacts": {},
            "evidence_ids": [],
            "cleanup_status": "not_requested",
        }
        workspace.write_run(state)
        return workspace

    @classmethod
    def load(cls, runs_dir: Path, run_id: str) -> "RunWorkspace":
        if not run_id or not RUN_ID_RE.match(run_id):
            raise fail("invalid_input", f"invalid run id: {run_id!r}")
        root = Path(runs_dir) / run_id
        if not (root / "run.json").is_file():
            raise fail("not_found", f"run not found: {run_id}", details={"run_id": run_id, "root": str(root)})
        return cls(root)

    def ensure_dirs(self) -> None:
        for relative in (
            "",
            "dexdump/raw",
            "dexdump/fixed",
            "dexdump/jadx",
            "assets",
            "logs",
            "logs/frida",
            "tmp",
            "records",
        ):
            (self.root / relative).mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ paths
    @property
    def run_id(self) -> str:
        return self.root.name

    @property
    def run_json(self) -> Path:
        return self.root / "run.json"

    @property
    def evidence_path(self) -> Path:
        return self.root / "evidence.jsonl"

    @property
    def events_path(self) -> Path:
        return self.root / "events.jsonl"

    @property
    def mutations_path(self) -> Path:
        return self.root / "mutations.json"

    @property
    def raw_dir(self) -> Path:
        return self.root / "dexdump" / "raw"

    @property
    def fixed_dir(self) -> Path:
        return self.root / "dexdump" / "fixed"

    @property
    def jadx_dir(self) -> Path:
        return self.root / "dexdump" / "jadx"

    @property
    def assets_dir(self) -> Path:
        return self.root / "assets"

    @property
    def tmp_dir(self) -> Path:
        return self.root / "tmp"

    @property
    def logs_dir(self) -> Path:
        return self.root / "logs"

    # ------------------------------------------------------------------ state
    def load_run(self) -> dict[str, Any]:
        try:
            with open(self.run_json, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except FileNotFoundError:
            raise fail("not_found", f"run state missing: {self.run_json}")
        except json.JSONDecodeError as exc:
            raise fail("integrity_mismatch", f"run state is not valid JSON: {exc}")

    def write_run(self, state: dict[str, Any]) -> None:
        state["updated_at"] = utc_now()
        self._atomic_write_json(self.run_json, state)

    def update_run(self, **changes: Any) -> dict[str, Any]:
        with self.lock():
            state = self.load_run()
            for key, value in changes.items():
                if key == "evidence_ids" and value is not None:
                    merged = list(dict.fromkeys(list(state.get("evidence_ids") or []) + list(value)))
                    state["evidence_ids"] = merged
                elif key == "attempts" and value is not None:
                    state["attempts"] = list(state.get("attempts") or []) + list(value)
                elif key == "artifacts" and value is not None:
                    merged_artifacts = dict(state.get("artifacts") or {})
                    merged_artifacts.update(value)
                    state["artifacts"] = merged_artifacts
                else:
                    state[key] = value
            self.write_run(state)
            return state

    # ------------------------------------------------------------------ evidence
    def append_evidence(self, record: dict[str, Any]) -> str:
        evidence_id = record.get("evidence_id")
        if not evidence_id:
            raise fail("invalid_input", "evidence record is missing evidence_id")
        semantic = canonical_json({key: value for key, value in record.items() if key != "evidence_id"})
        with self.lock():
            index = self._evidence_index()
            if evidence_id in index:
                if index[evidence_id] != semantic:
                    raise fail(
                        "integrity_mismatch",
                        f"evidence id {evidence_id} already exists with different content",
                        details={"evidence_id": evidence_id},
                    )
                return "duplicate"
            line = canonical_json(record)
            with open(self.evidence_path, "a", encoding="utf-8", newline="\n") as handle:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            state = self.load_run()
            ids = list(state.get("evidence_ids") or [])
            if evidence_id not in ids:
                ids.append(evidence_id)
            state["evidence_ids"] = ids
            self.write_run(state)
            return "added"

    def _evidence_index(self) -> dict[str, str]:
        index: dict[str, str] = {}
        if not self.evidence_path.is_file():
            return index
        with open(self.evidence_path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                evidence_id = record.get("evidence_id")
                if evidence_id:
                    index[evidence_id] = canonical_json(
                        {key: value for key, value in record.items() if key != "evidence_id"}
                    )
        return index

    def read_evidence(
        self,
        *,
        evidence_id: str | None = None,
        operation: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[dict[str, Any]], int]:
        records: list[dict[str, Any]] = []
        if not self.evidence_path.is_file():
            return records, 0
        with open(self.evidence_path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if evidence_id and record.get("evidence_id") != evidence_id:
                    continue
                if operation and record.get("operation") != operation:
                    continue
                records.append(record)
        total = len(records)
        return records[offset : offset + limit], total

    # ------------------------------------------------------------------ events / mutations
    def append_event(self, event: str, detail: dict[str, Any] | None = None) -> None:
        record = {"timestamp": utc_now(), "event": event, "detail": detail or {}}
        with open(self.events_path, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(canonical_json(record) + "\n")
            handle.flush()

    def load_mutations(self) -> list[dict[str, Any]]:
        if not self.mutations_path.is_file():
            return []
        try:
            with open(self.mutations_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            return list(data.get("mutations") or [])
        except (json.JSONDecodeError, OSError):
            return []

    def save_mutations(self, mutations: list[dict[str, Any]]) -> None:
        self._atomic_write_json(self.mutations_path, {"mutations": mutations})

    def add_mutation(self, record: dict[str, Any]) -> dict[str, Any]:
        with self.lock():
            mutations = self.load_mutations()
            if not record.get("mutation_id"):
                record["mutation_id"] = "mut_" + secrets.token_hex(6)
            if not record.get("timestamp"):
                record["timestamp"] = utc_now()
            record.setdefault("state", "applied")
            mutations.append(record)
            self.save_mutations(mutations)
            return record

    def update_mutation(self, mutation_id: str, **changes: Any) -> None:
        with self.lock():
            mutations = self.load_mutations()
            for record in mutations:
                if record.get("mutation_id") == mutation_id:
                    record.update(changes)
                    break
            self.save_mutations(mutations)

    # ------------------------------------------------------------------ helpers
    def _atomic_write_json(self, path: Path, value: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_name(path.name + ".tmp")
        with open(temp, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)

    @contextmanager
    def lock(self, timeout: float = 10.0) -> Iterator[None]:
        lock_path = self.root / "LOCK"
        deadline = time.monotonic() + max(0.0, timeout)
        acquired = False
        while True:
            try:
                fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(fd, f"{os.getpid()} {time.time()}\n".encode("ascii"))
                os.close(fd)
                acquired = True
                break
            except FileExistsError:
                # Recover a stale lock left by a crashed process.
                try:
                    age = time.time() - lock_path.stat().st_mtime
                    if age > 600:
                        lock_path.unlink(missing_ok=True)
                        continue
                except OSError:
                    pass
                if time.monotonic() >= deadline:
                    raise fail(
                        "conflict",
                        f"run is locked by another operation: {lock_path}",
                        details={"lock_path": str(lock_path)},
                    )
                time.sleep(0.05)
        try:
            yield
        finally:
            if acquired:
                try:
                    lock_path.unlink(missing_ok=True)
                except OSError:
                    pass

    def delete(self) -> None:
        root = self.root.resolve()
        if not re.search(r"run_[A-Za-z0-9_]+$", str(root)):
            raise fail("invalid_input", f"refusing to delete non-run directory: {root}")
        shutil.rmtree(root, ignore_errors=False)


def safe_join(base: Path, relative: str) -> Path:
    """Join a ZIP member into a base directory, rejecting traversal."""

    normalized = relative.replace("\\", "/").lstrip("/")
    candidate = (base / normalized).resolve()
    if base.resolve() not in candidate.parents and candidate != base.resolve():
        raise fail("invalid_input", f"path traversal rejected: {relative}")
    return candidate
