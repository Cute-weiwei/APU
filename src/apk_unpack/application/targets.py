"""Code namespaces corroborated by the target manifest, independent of appId."""
from __future__ import annotations

import re
from typing import Any


def target_namespaces(inspection: dict[str, Any]) -> list[str]:
    package = inspection.get("package") or {}
    manifest = inspection.get("manifest") or {}
    app_id = str(package.get("name") or manifest.get("package") or "").strip()
    result = [app_id] if app_id else []
    # A launcher can live outside the install package. Use its containing
    # namespace; for an unrelated appId also retain its immediate parent when
    # that parent has at least three segments (e.g. business.ui -> business).
    # Do not expand to a shared two-segment vendor/reverse-domain namespace.
    launcher = str(package.get("launchable_activity") or manifest.get("launchable_activity") or "").strip()
    if launcher.startswith("."):
        launcher = app_id + launcher
    elif launcher and "." not in launcher and app_id:
        launcher = app_id + "." + launcher
    if re.fullmatch(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*){2,}", launcher):
        namespace = launcher.rsplit(".", 1)[0]
        # Framework and known loader entry points cannot prove business code.
        if not namespace.startswith(("android.", "androidx.", "com.stub", "com.secneo", "com.qihoo", "s.h.e.l.l", "com.ijm")):
            if namespace not in result:
                result.append(namespace)
            if app_id and namespace != app_id and not namespace.startswith(app_id + "."):
                parent = namespace.rsplit(".", 1)[0]
                if len(parent.split(".")) >= 3 and parent not in result:
                    result.append(parent)
    return result
