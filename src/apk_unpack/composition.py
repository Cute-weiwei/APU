from __future__ import annotations

from pathlib import Path

from .application.workflow import ToolService
from .config import Config


def build_service(runs_dir: str | Path | None = None) -> ToolService:
    config = Config.load(runs_dir=runs_dir)
    return ToolService(config)
