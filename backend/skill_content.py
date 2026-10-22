"""Read a skill together with its local Markdown references."""
from __future__ import annotations

from pathlib import Path


def read_skill_bundle(path: str | Path) -> tuple[str, list[str]]:
    main = Path(path).resolve()
    text = main.read_text(encoding="utf-8", errors="strict")
    references = main.parent / "references"
    names: list[str] = []
    parts = [text]
    if references.is_dir():
        for file in sorted(references.rglob("*.md")):
            resolved = file.resolve()
            if not resolved.is_relative_to(main.parent):
                raise ValueError("skill reference escapes the skill directory")
            name = file.relative_to(main.parent).as_posix()
            parts.append(f"\n# Reference: {name}\n" + resolved.read_text(encoding="utf-8", errors="strict"))
            names.append(name)
    # The built-in instructions require these references. Never silently run
    # with only SKILL.md when a deployment has omitted part of the bundle.
    if main.parent.name == "unpack-android-apk":
        required = {
            "cases.md", "dex-forensics.md", "environment.md", "evidence.md",
            "frida-cookie-dump.md", "lessons.md", "memory-dump.md", "routing.md",
            "shell-signatures.md", "strategies.md",
        }
        missing = required - {Path(name).name for name in names}
        if missing:
            raise ValueError("missing required APK skill references: " + ", ".join(sorted(missing)))
    return "\n\n".join(parts), names
