"""Generic scanner for secrets in VS Code extension globalStorage directories."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Iterator

from aihound.core.scanner import (
    BaseScanner, CredentialFinding, ScanResult, StorageType,
)
from aihound.core.platform import (
    detect_platform, Platform, get_home, get_appdata, get_wsl_windows_home,
    get_xdg_config,
)
from aihound.core.redactor import mask_value
from aihound.core.permissions import (
    get_file_permissions, get_file_owner, assess_risk,
    get_file_mtime, describe_staleness,
)
from aihound.remediation import hint_manual
from aihound.scanners import register

logger = logging.getLogger("aihound.scanners.vscode_extensions")

# Extensions already covered by dedicated scanners — skip to avoid double reporting.
EXCLUDED_EXTENSIONS = {
    "github.copilot",
    "github.copilot-chat",
    "saoudrizwan.claude-dev",  # Cline
}

# Maximum JSON file size we're willing to parse (avoid data blobs, indexes, etc.)
MAX_JSON_SIZE = 1024 * 1024  # 1 MB

# Max recursion depth when walking extension directories / JSON structures.
MAX_DIR_DEPTH = 3
MAX_JSON_DEPTH = 8

SECRET_KEY_SUBSTRINGS = (
    "token", "key", "secret", "password", "apikey", "auth",
)

REMEDIATION = (
    "Use VS Code's SecretStorage API or OS keychain for extension credentials"
)


@register
class VSCodeExtensionsScanner(BaseScanner):
    def name(self) -> str:
        return "VS Code Extensions"

    def slug(self) -> str:
        return "vscode-extensions"

    def scan(self, show_secrets: bool = False) -> ScanResult:
        plat = detect_platform()
        result = ScanResult(scanner_name=self.name(), platform=plat.value)

        for base in self._get_global_storage_roots(plat):
            self._scan_global_storage(base, result, show_secrets)

        return result

    def _get_global_storage_roots(self, plat: Platform) -> list[Path]:
        roots: list[Path] = []

        if plat in (Platform.LINUX, Platform.WSL):
            roots.append(get_xdg_config() / "Code" / "User" / "globalStorage")
        if plat == Platform.MACOS:
            roots.append(
                get_home() / "Library" / "Application Support" / "Code"
                / "User" / "globalStorage"
            )
        if plat == Platform.WINDOWS:
            appdata = get_appdata()
            if appdata:
                roots.append(appdata / "Code" / "User" / "globalStorage")

        if plat == Platform.WSL:
            # Also scan Windows-side VS Code globalStorage via /mnt/c
            appdata = get_appdata()
            if appdata:
                roots.append(appdata / "Code" / "User" / "globalStorage")
            win_home = get_wsl_windows_home()
            if win_home:
                roots.append(
                    win_home / "AppData" / "Roaming" / "Code" / "User" / "globalStorage"
                )

        # De-duplicate while preserving order
        seen: set[str] = set()
        unique: list[Path] = []
        for r in roots:
            key = str(r)
            if key not in seen:
                seen.add(key)
                unique.append(r)
        return unique

    def _scan_global_storage(
        self, base: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        if not base.exists():
            logger.debug("globalStorage not found: %s", base)
            return

        logger.debug("Scanning globalStorage root: %s", base)
        try:
            entries = list(base.iterdir())
        except OSError as e:
            logger.debug("Could not list %s: %s", base, e)
            return

        for entry in entries:
            if not entry.is_dir():
                continue
            extension_id = entry.name
            if extension_id in EXCLUDED_EXTENSIONS:
                continue

            for json_file in self._iter_json_files(entry, depth=0):
                self._scan_extension_json(
                    json_file, extension_id, result, show_secrets,
                )

    def _iter_json_files(self, directory: Path, depth: int) -> Iterator[Path]:
        if depth > MAX_DIR_DEPTH:
            return
        try:
            children = list(directory.iterdir())
        except OSError:
            return

        for child in children:
            try:
                if child.is_file() and child.suffix.lower() == ".json":
                    try:
                        if child.stat().st_size <= MAX_JSON_SIZE:
                            yield child
                    except OSError:
                        continue
                elif child.is_dir():
                    yield from self._iter_json_files(child, depth + 1)
            except OSError:
                continue

    def _scan_extension_json(
        self, path: Path, extension_id: str,
        result: ScanResult, show_secrets: bool,
    ) -> None:
        logger.debug("Reading extension JSON: %s", path)
        perms = get_file_permissions(path)
        owner = get_file_owner(path)
        mtime = get_file_mtime(path)

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.debug("Could not parse %s: %s", path, e)
            return

        staleness_note = f"File last modified: {describe_staleness(mtime)}" if mtime else None

        for key_path, value in self._walk(data, prefix="", depth=0):
            # Only look at string values that match a secret-looking key
            if not isinstance(value, str):
                continue

            leaf_key = key_path.rsplit(".", 1)[-1].lower()
            if not any(sub in leaf_key for sub in SECRET_KEY_SUBSTRINGS):
                continue

            if not self._value_looks_secret(value):
                continue

            notes = [f"Extension: {extension_id}", f"JSON path: {key_path}"]
            if staleness_note:
                notes.append(staleness_note)

            storage = StorageType.PLAINTEXT_JSON
            result.findings.append(CredentialFinding(
                tool_name=self.name(),
                credential_type=f"{extension_id}:{key_path}",
                storage_type=storage,
                location=str(path),
                exists=True,
                risk_level=assess_risk(storage, path),
                value_preview=mask_value(value, show_full=show_secrets),
                raw_value=value if show_secrets else None,
                file_permissions=perms,
                file_owner=owner,
                file_modified=mtime,
                remediation=REMEDIATION,
                remediation_hint=hint_manual(REMEDIATION),
                notes=notes,
            ))

    def _walk(self, data, prefix: str, depth: int):
        """Yield (key_path, value) for every scalar in the JSON tree."""
        if depth > MAX_JSON_DEPTH:
            return
        if isinstance(data, dict):
            for k, v in data.items():
                new_prefix = f"{prefix}.{k}" if prefix else str(k)
                if isinstance(v, (dict, list)):
                    yield from self._walk(v, new_prefix, depth + 1)
                else:
                    yield new_prefix, v
        elif isinstance(data, list):
            for i, v in enumerate(data):
                new_prefix = f"{prefix}[{i}]" if prefix else f"[{i}]"
                if isinstance(v, (dict, list)):
                    yield from self._walk(v, new_prefix, depth + 1)
                else:
                    yield new_prefix, v

    @staticmethod
    def _value_looks_secret(value: str) -> bool:
        """Length 20+, mostly alphanumeric, not a path or URL."""
        if len(value) < 20:
            return False
        if value.startswith(("/", "\\", "http://", "https://", "file://")):
            return False
        # Reject things that clearly aren't tokens (spaces, lots of punctuation)
        if " " in value:
            return False
        alnum_ratio = sum(c.isalnum() or c in "-_.~+/=" for c in value) / len(value)
        return alnum_ratio >= 0.8
