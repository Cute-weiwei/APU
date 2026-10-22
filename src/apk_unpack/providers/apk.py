from __future__ import annotations

import fnmatch
import hashlib
import io
import os
import re
import zipfile
from pathlib import Path
from typing import Any, Iterable

from ..domain.errors import fail
from ..domain.jsonutil import sha256_file
from ..domain.workspace import safe_join
from .axml import AxmlError, extract_manifest
from .dex import dex_summary_for_apk_entry, parse_dex_header
from .host import HostRunner

MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_DEX_STRING_SCAN_BYTES = 64 * 1024 * 1024
DEX_HEADER_BYTES = 0x70

SHELLS: list[dict[str, Any]] = [
    {
        "id": "bangcle",
        "display": "Bangcle (梆梆)",
        "priority": 100,
        "entry_patterns": [
            r"^lib/[^/]+/libDexHelper",
            r"^lib/[^/]+/libdexjni\.so$",
            r"^lib/[^/]+/libprotectClass\.so$",
        ],
        "dex_strings": [b"com.secneo.apkwrapper.AP", b"com.secneo.apkwrapper.AW"],
        "manifest_strings": ["com.secneo.apkwrapper"],
    },
    {
        "id": "360",
        "display": "360 Jiagu (360加固)",
        "priority": 90,
        "entry_patterns": [
            r"^lib/[^/]+/libjiagu",
            r"^lib/[^/]+/libjgdtc\.so$",
            r"^lib/[^/]+/libzxprotect\.so$",
            r"^lib/[^/]+/libgeiri",
            r"^lib/[^/]+/libProxyService\.so$",
            r"^assets/\.jgapp$",
            r"^assets/\.jiagu",
            r"^assets/geiridata/",
        ],
        "dex_strings": [
            b"com.stub.StubApp",
            b"QHClassLoader",
            b"com.qihoo.util",
            b"com/Proxy/ShellApplication",
            b"com/Install/DexInstall",
            b"libgeiri.so",
            b"geiridata/",
        ],
        "manifest_strings": [
            "com.stub.StubApp",
            "com.qihoo",
            "QHClassLoader",
            "com.Proxy.ShellApplication",
            "com.Install.DexInstall",
        ],
    },
    {
        "id": "tencent",
        "display": "Tencent MTP (腾讯加固)",
        "priority": 80,
        "entry_patterns": [
            r"^lib/[^/]+/libshell-super\.",
            r"^lib/[^/]+/libshella-",
            r"^lib/[^/]+/libshellx-super\.",
            r"^assets/0OO00l",
            r"^assets/o0oooOO",
            r"^lib/[^/]+/libtup\.so$",
            r"^lib/[^/]+/libnqshield",
            r"^lib/[^/]+/libsgmain",
        ],
        "dex_strings": [b"WrapperProxyApplication", b"CustomerClassLoader"],
        "manifest_strings": [],
    },
    {
        "id": "ijiami",
        "display": "ijiami (爱加密)",
        "priority": 70,
        "entry_patterns": [
            r"^assets/ijiami\.",
            r"^assets/IJMDal\.Data$",
            r"^assets/ijm_lib/",
            r"^assets/libijmDataEncryption_",
            r"^lib/[^/]+/libijm-emulator\.so$",
            r"^lib/[^/]+/libijmdetect-drisk\.so$",
            r"^lib/[^/]+/libijiami_bobpay\.so$",
        ],
        "dex_strings": [
            b"s.h.e.l.l.S",
            b"s.h.e.l.l.N",
            b"com.ijm.dataencryption.DETool",
            b"libijiami_bobpay",
        ],
        "manifest_strings": ["s.h.e.l.l"],
    },
    {
        "id": "secneo",
        "display": "SecNeo SDK (爱加密内层)",
        "priority": 60,
        "entry_patterns": [r"^lib/[^/]+/libSdkHelper"],
        "dex_strings": [b"com.secneo.sdk.Helper", b"com.secneo.sdk.DexInstall", b"makeInMemoryDexElements"],
        "manifest_strings": ["com.secneo.sdk"],
    },
]

SHELL_BY_ID = {item["id"]: item for item in SHELLS}


def _natural_dex_key(name: str) -> tuple[int, str]:
    match = re.match(r"^classes(\d*)\.dex$", name)
    if not match:
        return (10**9, name)
    suffix = match.group(1)
    return (int(suffix) if suffix else 1, name)


class ApkInspector:
    def __init__(self, host: HostRunner, aapt: str | None = None):
        self.host = host
        self.aapt = aapt

    # ------------------------------------------------------------------ inspect
    def inspect(self, path: str | Path, *, deep_dex_scan: bool = True) -> dict[str, Any]:
        apk_path = Path(path).expanduser()
        if not apk_path.is_file():
            raise fail("invalid_input", f"APK not found: {apk_path}", details={"path": str(apk_path)})
        if apk_path.suffix.lower() in (".apks", ".xapk"):
            raise fail(
                "unsupported_target",
                f"{apk_path.suffix} bundles are not directly inspectable",
                remediation=(
                    "Pass the base APK (and keep sibling split APKs nearby for install-multiple), "
                    "or extract the bundle first."
                ),
                details={"path": str(apk_path)},
            )
        try:
            identity = {
                "path": str(apk_path),
                "sha256": sha256_file(apk_path),
                "size": apk_path.stat().st_size,
                "format": "apk",
            }
        except OSError as exc:
            raise fail("permission_denied", f"cannot read APK: {exc}", details={"path": str(apk_path)})

        limitations: list[str] = []
        coverage: dict[str, Any] = {"zip_directory": "complete"}
        try:
            archive = zipfile.ZipFile(apk_path)
        except (zipfile.BadZipFile, OSError) as exc:
            raise fail("unsupported_target", f"not a readable APK/ZIP: {exc}", details={"path": str(apk_path)})

        with archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            name_set = set(names)
            abis = sorted(
                {
                    match.group(1)
                    for name in names
                    if (match := re.match(r"^lib/([^/]+)/", name)) and match.group(1)
                }
            )
            dex_entries = self._inspect_dex_entries(archive, infos, limitations)
            manifest, manifest_status = self._inspect_manifest(archive, apk_path, limitations)
            coverage["manifest"] = manifest_status
            if manifest.get("parser") == "aapt+xmltree":
                coverage["manifest"] = "complete"
            framework_info = self._detect_frameworks(names, archive)
            shell_matches = self._detect_shells(names, archive, manifest, deep_dex_scan, limitations)
            shell_result = self._resolve_shells(shell_matches)
            suspicious_application = self._suspicious_application_class(manifest.get("application_class"))
            packed = self._packed(
                dex_entries,
                shell_result,
                suspicious_application=suspicious_application,
            )
            coverage["dex_headers"] = (
                "complete"
                if all(item.get("header") for item in dex_entries) or not dex_entries
                else "partial"
            )
            if deep_dex_scan and "dex_string_scan_budget_exhausted" in limitations:
                coverage["dex_strings"] = "partial"
            else:
                coverage["dex_strings"] = "complete" if deep_dex_scan else "skipped"

        wgt_entries = [
            name
            for name in names
            if re.match(r"^assets/__UNI__.*\.wgt$", name, re.IGNORECASE)
        ]
        split_apk = not dex_entries and bool(manifest.get("package"))
        if split_apk:
            limitations.append("No top-level classes*.dex: this may be a split APK or an app using a non-standard layout.")
        return {
            "identity": identity,
            "manifest": manifest,
            "package": {
                "name": manifest.get("package"),
                "version_code": manifest.get("version_code"),
                "version_name": manifest.get("version_name"),
                "min_sdk": manifest.get("min_sdk"),
                "target_sdk": manifest.get("target_sdk"),
                "launchable_activity": manifest.get("launchable_activity"),
                "application_class": manifest.get("application_class"),
                "app_component_factory": manifest.get("app_component_factory"),
                "permission_count": len(manifest.get("permissions") or []),
            },
            "abis": abis,
            "frameworks": framework_info["frameworks"],
            "packing": {
                **shell_result,
                "packed": packed,
                "application_class_suspicious": suspicious_application,
                "stub_class_count": sum(
                    (item.get("header") or {}).get("class_defs_size", 0) for item in dex_entries
                ),
                "encrypted_tail_bytes": max(
                    (item.get("encrypted_tail_bytes", 0) for item in dex_entries), default=0
                ),
            },
            "shells": shell_matches,
            "dex_entries": dex_entries,
            "wgt_entries": wgt_entries,
            "split_apk": split_apk,
            "coverage": coverage,
            "limitations": limitations,
        }

    # ------------------------------------------------------------------ dex / manifest
    def _inspect_dex_entries(
        self,
        archive: zipfile.ZipFile,
        infos: list[zipfile.ZipInfo],
        limitations: list[str],
    ) -> list[dict[str, Any]]:
        dex_infos = [
            item
            for item in infos
            if "/" not in item.filename and re.match(r"^classes\d*\.dex$", item.filename)
        ]
        dex_infos.sort(key=lambda item: _natural_dex_key(item.filename))
        entries: list[dict[str, Any]] = []
        for info in dex_infos:
            try:
                with archive.open(info) as handle:
                    header_bytes = handle.read(DEX_HEADER_BYTES)
            except (OSError, zipfile.BadZipFile) as exc:
                limitations.append(f"cannot read {info.filename} header: {exc}")
                header_bytes = b""
            summary = dex_summary_for_apk_entry(info.file_size, header_bytes)
            header = summary["header"]
            entries.append(
                {
                    "name": info.filename,
                    "entry_size": info.file_size,
                    "compressed_size": info.compress_size,
                    "header": header,
                    "packed_stub": summary["packed_stub"],
                    "encrypted_tail_bytes": summary["encrypted_tail_bytes"],
                }
            )
        return entries

    def _inspect_manifest(
        self,
        archive: zipfile.ZipFile,
        apk_path: Path,
        limitations: list[str],
    ) -> tuple[dict[str, Any], str]:
        manifest: dict[str, Any] = {"parser": None}
        status = "unsupported"
        try:
            info = archive.getinfo("AndroidManifest.xml")
            if info.file_size > MAX_MANIFEST_BYTES:
                limitations.append("AndroidManifest.xml exceeds the 16 MiB inspection budget.")
            else:
                with archive.open(info) as handle:
                    data = handle.read()
                manifest = extract_manifest(data)
                status = "complete" if manifest.get("package") else "partial"
        except (KeyError, AxmlError, OSError, zipfile.BadZipFile) as exc:
            limitations.append(f"AXML manifest parse failed: {exc}")

        if self.aapt:
            badging = self.host.run([self.aapt, "dump", "badging", str(apk_path)], timeout=30)
            if badging.ok and badging.stdout:
                parsed = _parse_aapt_badging(badging.stdout)
                for key, value in parsed.items():
                    if value is not None and not manifest.get(key):
                        manifest[key] = value
                if parsed.get("package") and not manifest.get("package"):
                    manifest["package"] = parsed["package"]
                manifest.setdefault("parser", "aapt")
                status = "complete" if manifest.get("package") else status
            else:
                limitations.append("aapt dump badging failed; used AXML fallback only.")
            xmltree = self.host.run(
                [self.aapt, "dump", "xmltree", str(apk_path), "AndroidManifest.xml"], timeout=30
            )
            if xmltree.ok and xmltree.stdout:
                details = _parse_aapt_xmltree(xmltree.stdout)
                for key in ("application_class", "app_component_factory", "launchable_activity"):
                    if details.get(key) and not manifest.get(key):
                        manifest[key] = details[key]
                manifest["parser"] = "aapt+xmltree" if manifest.get("parser") == "aapt" else "axml+aapt"
        else:
            limitations.append("aapt is not configured; manifest fields rely on the built-in AXML parser.")

        defaults = {
            "package": None,
            "version_code": None,
            "version_name": None,
            "min_sdk": None,
            "target_sdk": None,
            "launchable_activity": None,
            "application_class": None,
            "app_component_factory": None,
            "activities": [],
            "permissions": [],
        }
        for key, value in defaults.items():
            manifest.setdefault(key, value)
        return manifest, status

    # ------------------------------------------------------------------ frameworks
    @staticmethod
    def _detect_frameworks(names: list[str], archive: zipfile.ZipFile) -> dict[str, Any]:
        frameworks: list[dict[str, Any]] = []
        uni_indicators = [
            name
            for name in names
            if re.match(r"^assets/__UNI__.*\.wgt$", name, re.IGNORECASE)
            or name.startswith("assets/data/dcloud")
            or re.match(r"^lib/[^/]+/libweex", name)
        ]
        if uni_indicators:
            frameworks.append({"name": "uni-app", "indicators": uni_indicators[:8]})
        flutter_indicators = [
            name
            for name in names
            if name.startswith("assets/flutter_assets/") or re.match(r"^lib/[^/]+/libflutter\.so$", name)
        ]
        if flutter_indicators:
            frameworks.append({"name": "flutter", "indicators": flutter_indicators[:8]})
        rn_indicators = [
            name
            for name in names
            if name == "assets/index.android.bundle" or re.match(r"^lib/[^/]+/lib(hermes|react_native)", name)
        ]
        if rn_indicators:
            frameworks.append({"name": "react-native", "indicators": rn_indicators[:8]})
        return {"frameworks": frameworks}

    # ------------------------------------------------------------------ shell detection
    def _detect_shells(
        self,
        names: list[str],
        archive: zipfile.ZipFile,
        manifest: dict[str, Any],
        deep_dex_scan: bool,
        limitations: list[str],
    ) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        for shell in SHELLS:
            for pattern in shell["entry_patterns"]:
                compiled = re.compile(pattern, re.IGNORECASE)
                for name in names:
                    if compiled.search(name):
                        matches.append(
                            {
                                "shell": shell["id"],
                                "display": shell["display"],
                                "kind": "zip-entry",
                                "indicator": name,
                                "location": "apk",
                            }
                        )
                        break
            for needle in shell["manifest_strings"]:
                for field in ("application_class", "app_component_factory"):
                    value = str(manifest.get(field) or "")
                    if needle.lower() in value.lower():
                        matches.append(
                            {
                                "shell": shell["id"],
                                "display": shell["display"],
                                "kind": "manifest",
                                "indicator": f"{field}={value}",
                                "location": "AndroidManifest.xml",
                            }
                        )
        if deep_dex_scan:
            matches.extend(self._scan_dex_strings(archive, names, limitations))
        # Stable de-duplication by shell + indicator.
        unique: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for match in matches:
            key = (match["shell"], str(match["indicator"]))
            if key in seen:
                continue
            seen.add(key)
            unique.append(match)
        return unique

    def _scan_dex_strings(
        self,
        archive: zipfile.ZipFile,
        names: list[str],
        limitations: list[str],
    ) -> list[dict[str, Any]]:
        dex_names = [name for name in names if "/" not in name and re.match(r"^classes\d*\.dex$", name)]
        patterns: list[tuple[str, bytes]] = []
        for shell in SHELLS:
            for needle in shell["dex_strings"]:
                patterns.append((shell["id"], needle))
        found: set[tuple[str, bytes]] = set()
        budget = MAX_DEX_STRING_SCAN_BYTES
        exhausted = False
        for name in dex_names:
            if len(found) >= len(patterns):
                break
            try:
                with archive.open(name) as handle:
                    carry = b""
                    while budget > 0:
                        chunk = handle.read(min(4 * 1024 * 1024, budget))
                        if not chunk:
                            break
                        budget -= len(chunk)
                        data = carry + chunk
                        for shell_id, needle in patterns:
                            if (shell_id, needle) in found:
                                continue
                            if needle in data:
                                found.add((shell_id, needle))
                        carry = data[-128:]
                    if budget <= 0:
                        exhausted = True
                        break
            except (OSError, zipfile.BadZipFile) as exc:
                limitations.append(f"cannot scan {name} for shell strings: {exc}")
        if exhausted:
            limitations.append("Shell DEX-string scan hit the 64 MiB budget; deeper entries were not scanned.")
            limitations.append("dex_string_scan_budget_exhausted")
        matches: list[dict[str, Any]] = []
        for shell_id, needle in found:
            shell = SHELL_BY_ID[shell_id]
            matches.append(
                {
                    "shell": shell_id,
                    "display": shell["display"],
                    "kind": "dex-string",
                    "indicator": needle.decode("utf-8", errors="replace"),
                    "location": "classes*.dex",
                }
            )
        return matches

    @staticmethod
    def _resolve_shells(matches: list[dict[str, Any]]) -> dict[str, Any]:
        by_shell: dict[str, list[dict[str, Any]]] = {}
        for match in matches:
            by_shell.setdefault(match["shell"], []).append(match)
        layers = sorted(
            (
                {
                    "shell": shell_id,
                    "display": SHELL_BY_ID[shell_id]["display"],
                    "priority": SHELL_BY_ID[shell_id]["priority"],
                    "match_count": len(items),
                }
                for shell_id, items in by_shell.items()
            ),
            key=lambda item: -item["priority"],
        )
        primary = layers[0]["shell"] if layers else "unknown"
        display = layers[0]["display"] if layers else "unknown"
        notes: list[str] = []
        if "bangcle" in by_shell and len(layers) > 1:
            notes.append("libDexHelper present: treat as Bangcle regardless of other shell indicators.")
        if "360" in by_shell and "secneo" in by_shell:
            notes.append("360 outer + SecNeo inner: rename the inner SecNeo library before attaching Frida.")
        if not layers:
            notes.append("No known shell signature matched; inspect stability before choosing a runtime strategy.")
        strong = any(item["kind"] in ("zip-entry", "dex-string") for item in matches)
        manifest_only = any(item["kind"] == "manifest" for item in matches) and not strong
        confidence = "observed" if strong else ("derived" if manifest_only else "inferred")
        return {
            "primary": primary,
            "display": display,
            "mixed": len(layers) > 1,
            "layers": layers,
            "confidence": confidence,
            "precedence_notes": notes,
        }

    @staticmethod
    def _suspicious_application_class(value: Any) -> bool:
        """Flag loader-style Application classes used by unknown shells.

        Legitimate apps can use third-party Application classes, so only
        loader/shell-like names are treated as evidence, never a bare
        third-party package.
        """
        text = str(value or "").strip()
        if not text:
            return False
        return bool(
            re.search(
                r"(?:^|[./])(?:shell|stub|loader|proxy|wrapper|dexinstall|protect|jiagu|geiri)",
                text,
                re.IGNORECASE,
            )
        )

    @staticmethod
    def _packed(
        dex_entries: list[dict[str, Any]],
        shell_result: dict[str, Any],
        *,
        suspicious_application: bool = False,
    ) -> bool | None:
        # A known shell always means the app is packed, even when the outer DEX
        # has more than ten classes. Some shells (for example Geiri/360) keep
        # a large but nearly empty loader DEX.
        if shell_result.get("primary") not in (None, "", "unknown"):
            return True
        if suspicious_application:
            return True
        parsed = [item for item in dex_entries if item.get("header")]
        if parsed:
            if any(item.get("packed_stub") for item in parsed):
                return True
            if sum((item.get("header") or {}).get("class_defs_size", 0) for item in parsed) <= 10:
                return True
            return False
        return None

    # ------------------------------------------------------------------ asset extraction
    def extract_assets(
        self,
        path: str | Path,
        output_dir: str | Path,
        *,
        patterns: Iterable[str] | None = None,
        include_wgt: bool = True,
        overwrite: bool = False,
        max_total_bytes: int = 512 * 1024 * 1024,
    ) -> dict[str, Any]:
        apk_path = Path(path).expanduser()
        out_dir = Path(output_dir).expanduser()
        if not apk_path.is_file():
            raise fail("invalid_input", f"APK not found: {apk_path}")
        patterns = list(patterns or [])
        if out_dir.exists() and any(out_dir.iterdir()) and not overwrite:
            raise fail("conflict", f"output directory is not empty: {out_dir}")
        out_dir.mkdir(parents=True, exist_ok=True)
        extracted: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        total = 0
        try:
            archive = zipfile.ZipFile(apk_path)
        except (zipfile.BadZipFile, OSError) as exc:
            raise fail("unsupported_target", f"not a readable APK/ZIP: {exc}")
        with archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                name = info.filename
                selected = False
                if patterns:
                    selected = any(fnmatch.fnmatch(name, pattern) for pattern in patterns)
                else:
                    # uni-app also ships expanded apps/*/www trees, and hybrid
                    # apps can keep business code under shopcore or other assets.
                    selected = name.startswith("assets/") and (
                        include_wgt or not name.lower().endswith(".wgt")
                    )
                if not selected:
                    continue
                if info.file_size > max_total_bytes - total:
                    skipped.append({"name": name, "reason": "asset size budget exceeded", "size": info.file_size})
                    continue
                try:
                    destination = safe_join(out_dir, name)
                except Exception as exc:
                    skipped.append({"name": name, "reason": str(exc), "size": info.file_size})
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with archive.open(info) as source, open(destination, "wb") as sink:
                        digest = hashlib.sha256()
                        written = 0
                        while True:
                            chunk = source.read(4 * 1024 * 1024)
                            if not chunk:
                                break
                            sink.write(chunk)
                            digest.update(chunk)
                            written += len(chunk)
                    total += written
                    record = {
                        "name": name,
                        "path": str(destination),
                        "size": written,
                        "sha256": digest.hexdigest(),
                    }
                    extracted.append(record)
                    if name.lower().endswith(".wgt"):
                        wgt_dir = out_dir / (destination.stem + ".extracted")
                        record["extracted_dir"] = str(wgt_dir)
                        record["wgt_members"] = _extract_wgt(destination, wgt_dir)
                except (OSError, zipfile.BadZipFile) as exc:
                    skipped.append({"name": name, "reason": str(exc), "size": info.file_size})
        return {
            "apk": str(apk_path),
            "output_dir": str(out_dir),
            "files": extracted,
            "skipped": skipped,
            "total_bytes": total,
            "coverage": "complete" if not skipped else "partial",
        }


def _extract_wgt(path: Path, out_dir: Path) -> list[dict[str, Any]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    members: list[dict[str, Any]] = []
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                destination = safe_join(out_dir, info.filename)
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source, open(destination, "wb") as sink:
                    while True:
                        chunk = source.read(4 * 1024 * 1024)
                        if not chunk:
                            break
                        sink.write(chunk)
                members.append({"name": info.filename, "path": str(destination), "size": info.file_size})
    except (zipfile.BadZipFile, OSError):
        pass
    return members


def _parse_aapt_badging(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for line in text.splitlines():
        match = re.match(r"package: name='([^']*)' versionCode='([^']*)' versionName='([^']*)'", line)
        if match:
            result["package"] = match.group(1)
            try:
                result["version_code"] = int(match.group(2))
            except ValueError:
                result["version_code"] = None
            result["version_name"] = match.group(3)
            continue
        match = re.match(r"sdkVersion:'([^']*)'", line)
        if match:
            result["min_sdk"] = _to_int(match.group(1))
            continue
        match = re.match(r"targetSdkVersion:'([^']*)'", line)
        if match:
            result["target_sdk"] = _to_int(match.group(1))
            continue
        match = re.match(r"launchable-activity: name='([^']*)'", line)
        if match:
            result["launchable_activity"] = match.group(1)
    return result


def _parse_aapt_xmltree(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    current = None
    for line in text.splitlines():
        element = re.match(r"^\s*E: ([\w.$-]+)", line)
        if element:
            current = element.group(1).split(".")[-1]
            continue
        if not line.strip().startswith("A:"):
            continue
        attr_name = None
        value: Any = None
        typed = re.match(
            r"^\s*A: .*?:([A-Za-z0-9_]+)\(0x[0-9a-fA-F]+\)=(.*)$",
            line,
        )
        if typed:
            attr_name = typed.group(1)
            rest = typed.group(2).strip()
            quoted = re.search(r'"([^"]*)"', rest)
            if quoted:
                value = quoted.group(1)
            else:
                typed_int = re.match(r"\(type 0x1[01]\)(0x[0-9a-fA-F]+|-?\d+)", rest)
                value = _to_int(typed_int.group(1)) if typed_int else rest
        else:
            plain = re.match(r'^\s*A: ([\w.-]+)="([^"]*)"', line)
            if plain:
                attr_name, value = plain.group(1), plain.group(2)
        if current == "application":
            if attr_name == "name" and value:
                result.setdefault("application_class", value)
            elif attr_name == "appComponentFactory" and value:
                result.setdefault("app_component_factory", value)
        if attr_name == "name" and current in ("activity", "activity-alias") and value:
            result.setdefault("launchable_activity", value)
    return result


def _to_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        text = str(value).strip()
        return int(text, 0) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None
