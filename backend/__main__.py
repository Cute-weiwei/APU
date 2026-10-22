from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import signal
import sys
import time
from pathlib import Path
from typing import Any

from .config import BackendConfig
from .db import Database
from .engines import EngineResult
from .events import EventBus
from .jobs import JobManager
from .lessons import record_job_lesson
from .security import chmod_private, hash_password
from .server import BackendApp, serve


def _config(args: argparse.Namespace) -> BackendConfig:
    return BackendConfig.load(config_path=args.config, data_dir=args.data_dir)


def cmd_serve(args: argparse.Namespace) -> int:
    config = _config(args)
    app = BackendApp(config)
    app.initialize()

    def stop(signum: int, frame: object) -> None:
        raise KeyboardInterrupt()

    try:
        signal.signal(signal.SIGTERM, stop)
    except (AttributeError, ValueError, OSError):
        pass
    try:
        serve(app)
    except KeyboardInterrupt:
        app.stop()
    return 0


def cmd_create_admin(args: argparse.Namespace) -> int:
    config = _config(args)
    database = Database(config.db_path)
    database.initialize()
    username = args.username or config.admin_user or "admin"
    password = args.password or config.admin_password
    generated = False
    if not password:
        password = secrets.token_urlsafe(12)
        generated = True
        path = config.data_dir / "admin_password.txt"
        path.write_text(password + "\n", encoding="utf-8")
        chmod_private(path)
    salt, digest = hash_password(password)
    existing = database.get_user_by_name(username)
    if existing:
        database.update_user(int(existing["id"]), password_hash=digest, salt=salt, role="admin", disabled=0)
        print(f"admin reset: {username}")
    else:
        database.create_user(username, digest, salt, "admin")
        print(f"admin created: {username}")
    if generated:
        print(f"password written to {config.data_dir / 'admin_password.txt'}")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    config = _config(args)
    database = Database(config.db_path)
    database.initialize()
    app = BackendApp(config)
    app.database = database
    app.jobs = JobManager(config, database, app.bus)
    app.jobs.seed_catalog()
    report = {
        "config": config.public(),
        "engines": app.engine_public(),
        "users": database.count_users(),
        "jobs": database.job_counts(),
        "health": app.health(),
        "agent_doctor": app.jobs.service.doctor(),
    }
    print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
    return 0


def cmd_gc(args: argparse.Namespace) -> int:
    config = _config(args)
    database = Database(config.db_path)
    database.initialize()
    deleted_sessions = database.cleanup_sessions()
    cutoff = time.time() - max(1, config.retention_days) * 86400
    removed_jobs = 0
    removed_uploads = 0
    for job in database.list_jobs(limit=100000)[0]:
        created = job.get("created_at")
        if not created:
            continue
        try:
            import datetime

            timestamp = datetime.datetime.fromisoformat(created.replace("Z", "+00:00")).timestamp()
        except ValueError:
            continue
        if timestamp >= cutoff:
            continue
        if job.get("status") in ("queued", "running"):
            continue
        shutil.rmtree(config.jobs_dir / job["id"], ignore_errors=True)
        database.delete_job(job["id"])
        removed_jobs += 1
    for upload in database.list_uploads(limit=100000):
        try:
            import datetime

            timestamp = datetime.datetime.fromisoformat(upload["created_at"].replace("Z", "+00:00")).timestamp()
        except (ValueError, KeyError):
            continue
        if timestamp < cutoff:
            try:
                Path(upload["path"]).unlink(missing_ok=True)
                Path(upload["path"]).parent.rmdir()
            except OSError:
                pass
            database.delete_upload(upload["id"])
            removed_uploads += 1
    print(
        json.dumps(
            {
                "sessions_removed": deleted_sessions,
                "jobs_removed": removed_jobs,
                "uploads_removed": removed_uploads,
                "retention_days": config.retention_days,
            },
            ensure_ascii=False,
        )
    )
    return 0


def cmd_lessons_backfill(args: argparse.Namespace) -> int:
    """Generate automatic lessons for jobs that ran before auto-lessons existed."""
    config = _config(args)
    database = Database(config.db_path)
    database.initialize()
    app = BackendApp(config)
    app.database = database
    app.jobs = JobManager(config, database, app.bus)
    app.jobs.seed_catalog()
    lessons = app.jobs.service.lessons
    existing = lessons.list(limit=500).get("lessons") or []
    seen_runs = {
        str(example.get("run_id"))
        for lesson in existing
        for example in (lesson.get("examples") or [])
        if example.get("run_id")
    }
    counts = {"added": 0, "merged": 0, "existing": 0, "skipped": 0}
    details: list[dict[str, Any]] = []
    for job in database.list_jobs(limit=100000)[0]:
        status = job.get("status")
        if status not in ("succeeded", "partial", "failed"):
            counts["skipped"] += 1
            continue
        run_id = job.get("run_id")
        if not run_id or run_id in seen_runs:
            counts["skipped"] += 1
            continue
        run_dir = config.runs_dir / run_id
        if not run_dir.is_dir():
            counts["skipped"] += 1
            continue
        outcome = {"succeeded": "success", "partial": "partial", "failed": "failed"}.get(status, "failed")
        error = job.get("error") if isinstance(job.get("error"), dict) else None
        result = EngineResult(outcome, run_id=run_id, error=error)
        events: list[tuple[str, dict[str, Any]]] = []

        def emit(kind: str, message: str = "", data: dict[str, Any] | None = None) -> None:
            events.append((kind, data or {}))

        lesson = record_job_lesson(
            lessons,
            job=job,
            result=result,
            run_id=run_id,
            run_dir=run_dir,
            emit=emit,
        )
        status_event = next(
            (
                data.get("status")
                for kind, data in events
                if kind == "lesson_recorded"
            ),
            None,
        )
        if status_event in counts:
            counts[status_event] += 1
        elif lesson:
            counts["merged"] += 1
        else:
            counts["skipped"] += 1
        details.append(
            {
                "job_id": job.get("id"),
                "run_id": run_id,
                "status": status_event or ("skipped" if lesson is None else "merged"),
                "lesson_id": (lesson or {}).get("lesson_id"),
                "title": (lesson or {}).get("title"),
            }
        )
        if lesson:
            examples = lesson.get("examples") or []
            for example in examples:
                if example.get("run_id"):
                    seen_runs.add(str(example["run_id"]))
    print(
        json.dumps(
            {
                "counts": counts,
                "lessons_total": lessons.stats().get("total"),
                "details": details if args.verbose else details[:20],
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="apu-web", description="APK Unpack web backend")
    parser.add_argument("--config", help="JSON config path")
    parser.add_argument("--data-dir", help="Override the data directory")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve", help="Start the HTTP backend")
    create = sub.add_parser("create-admin", help="Create or reset an admin user")
    create.add_argument("--username", default=None)
    create.add_argument("--password", default=None)
    sub.add_parser("doctor", help="Print an environment report")
    sub.add_parser("gc", help="Remove expired sessions/jobs/uploads")
    backfill = sub.add_parser("lessons-backfill", help="Auto-generate lessons for historical jobs")
    backfill.add_argument("--verbose", action="store_true", help="Include every job in the report")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    commands = {
        "serve": cmd_serve,
        "create-admin": cmd_create_admin,
        "doctor": cmd_doctor,
        "gc": cmd_gc,
        "lessons-backfill": cmd_lessons_backfill,
    }
    return commands[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
