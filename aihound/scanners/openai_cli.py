"""Scanner for OpenAI / Codex CLI credentials."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("aihound.scanners.openai_cli")

from aihound.core.scanner import (
    BaseScanner, CredentialFinding, ScanResult, StorageType,
)
from aihound.core.platform import (
    detect_platform, Platform, get_home, get_appdata, get_wsl_windows_home,
)
from aihound.core.redactor import mask_value
from aihound.core.permissions import (
    get_file_permissions, get_file_owner, assess_risk,
    get_file_mtime, describe_staleness,
)
from aihound.remediation import hint_migrate_to_env
from aihound.scanners import register


SECRET_KEY_TOKENS = ("token", "key", "secret", "api_key", "apikey", "access_key", "refresh")


@register
class OpenAICLIScanner(BaseScanner):
    def name(self) -> str:
        return "OpenAI/Codex CLI"

    def slug(self) -> str:
        return "openai-cli"

    def scan(self, show_secrets: bool = False) -> ScanResult:
        plat = detect_platform()
        result = ScanResult(scanner_name=self.name(), platform=plat.value)

        # Plaintext api_key files
        for path in self._get_plaintext_paths(plat):
            self._scan_plaintext(path, result, show_secrets)

        # JSON config files (single files)
        for path in self._get_json_paths(plat):
            self._scan_json_file(path, result, show_secrets)

        # Directory glob: .codex dirs and %APPDATA%/OpenAI dirs
        for directory in self._get_json_directories(plat):
            if not directory.exists() or not directory.is_dir():
                continue
            try:
                for json_path in directory.glob("*.json"):
                    self._scan_json_file(json_path, result, show_secrets)
            except OSError as e:
                result.errors.append(f"Failed to enumerate {directory}: {e}")

        return result

    def _get_plaintext_paths(self, plat: Platform) -> list[Path]:
        paths: list[Path] = []
        home = get_home()

        paths.append(home / ".openai" / "api_key")

        if plat == Platform.WSL:
            win_home = get_wsl_windows_home()
            if win_home:
                paths.append(win_home / ".openai" / "api_key")
            appdata = get_appdata()
            if appdata:
                paths.append(appdata / "OpenAI" / "api_key")
        elif plat == Platform.WINDOWS:
            appdata = get_appdata()
            if appdata:
                paths.append(appdata / "OpenAI" / "api_key")

        return paths

    def _get_json_paths(self, plat: Platform) -> list[Path]:
        paths: list[Path] = []
        home = get_home()

        paths.append(home / ".openai" / "auth.json")

        if plat == Platform.WSL:
            win_home = get_wsl_windows_home()
            if win_home:
                paths.append(win_home / ".openai" / "auth.json")
            appdata = get_appdata()
            if appdata:
                paths.append(appdata / "OpenAI" / "auth.json")
        elif plat == Platform.WINDOWS:
            appdata = get_appdata()
            if appdata:
                paths.append(appdata / "OpenAI" / "auth.json")

        return paths

    def _get_json_directories(self, plat: Platform) -> list[Path]:
        dirs: list[Path] = []
        home = get_home()

        dirs.append(home / ".codex")

        if plat == Platform.WSL:
            win_home = get_wsl_windows_home()
            if win_home:
                dirs.append(win_home / ".codex")
            appdata = get_appdata()
            if appdata:
                dirs.append(appdata / "OpenAI")
        elif plat == Platform.WINDOWS:
            appdata = get_appdata()
            if appdata:
                dirs.append(appdata / "OpenAI")

        return dirs

    def _scan_plaintext(
        self, path: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        if not path.exists():
            logger.debug("Plaintext key file not found: %s", path)
            return

        logger.debug("Reading plaintext key file: %s", path)
        perms = get_file_permissions(path)
        owner = get_file_owner(path)
        mtime = get_file_mtime(path)
        storage = StorageType.PLAINTEXT_FILE

        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError as e:
            logger.warning("Failed to read %s: %s", path, e)
            result.errors.append(f"Failed to read {path}: {e}")
            return

        if not value:
            return

        notes: list[str] = []
        if mtime:
            notes.append(f"File last modified: {describe_staleness(mtime)}")

        result.findings.append(CredentialFinding(
            tool_name=self.name(),
            credential_type="openai_api_key",
            storage_type=storage,
            location=str(path),
            exists=True,
            risk_level=assess_risk(storage, path),
            value_preview=mask_value(value, show_full=show_secrets),
            raw_value=value if show_secrets else None,
            file_permissions=perms,
            file_owner=owner,
            file_modified=mtime,
            remediation="Use OPENAI_API_KEY environment variable instead of plaintext file",
            remediation_hint=hint_migrate_to_env(["OPENAI_API_KEY"], str(path)),
            notes=notes,
        ))

    def _scan_json_file(
        self, path: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        if not path.exists():
            logger.debug("OpenAI JSON file not found: %s", path)
            return

        logger.debug("Reading OpenAI JSON file: %s", path)
        perms = get_file_permissions(path)
        owner = get_file_owner(path)
        mtime = get_file_mtime(path)

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to parse %s: %s", path, e)
            result.errors.append(f"Failed to parse {path}: {e}")
            return

        self._walk_json(data, path, perms, owner, mtime, result, show_secrets, key_path="")

    def _walk_json(
        self,
        data,
        path: Path,
        perms: Optional[str],
        owner: Optional[str],
        mtime,
        result: ScanResult,
        show_secrets: bool,
        key_path: str,
    ) -> None:
        storage = StorageType.PLAINTEXT_JSON

        if isinstance(data, dict):
            for k, v in data.items():
                if not isinstance(k, str):
                    continue
                sub_path = f"{key_path}.{k}" if key_path else k

                if isinstance(v, str) and v:
                    k_lower = k.lower()
                    if any(tok in k_lower for tok in SECRET_KEY_TOKENS) and len(v) > 8:
                        notes = [f"JSON key path: {sub_path}"]
                        if mtime:
                            notes.append(f"File last modified: {describe_staleness(mtime)}")
                        result.findings.append(CredentialFinding(
                            tool_name=self.name(),
                            credential_type=f"openai:{k}",
                            storage_type=storage,
                            location=str(path),
                            exists=True,
                            risk_level=assess_risk(storage, path),
                            value_preview=mask_value(v, show_full=show_secrets),
                            raw_value=v if show_secrets else None,
                            file_permissions=perms,
                            file_owner=owner,
                            file_modified=mtime,
                            remediation="Use OPENAI_API_KEY environment variable instead of plaintext file",
                            remediation_hint=hint_migrate_to_env(["OPENAI_API_KEY"], str(path)),
                            notes=notes,
                        ))
                elif isinstance(v, (dict, list)):
                    self._walk_json(v, path, perms, owner, mtime, result, show_secrets, sub_path)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                sub_path = f"{key_path}[{i}]"
                if isinstance(item, (dict, list)):
                    self._walk_json(item, path, perms, owner, mtime, result, show_secrets, sub_path)
