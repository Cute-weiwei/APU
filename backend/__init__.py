"""APK unpack web backend."""

from __future__ import annotations

import sys
from pathlib import Path

__version__ = "0.1.0"

_AGENT_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_AGENT_SRC) not in sys.path:
    sys.path.insert(0, str(_AGENT_SRC))
