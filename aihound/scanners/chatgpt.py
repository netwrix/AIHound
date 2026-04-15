"""Scanner for ChatGPT Desktop credentials."""

from __future__ import annotations

import json
from pathlib import Path

from aihound.core.scanner import (
    BaseScanner, CredentialFinding, ScanResult, StorageType,
)
from aihound.core.platform import (
    detect_platform, Platform, get_home, get_appdata, get_wsl_windows_home,
)
from aihound.core.redactor import mask_value
from aihound.core.permissions import get_file_permissions, get_file_owner, assess_risk
from aihound.scanners import register


@register
class ChatGPTScanner(BaseScanner):
    def name(self) -> str:
        return "ChatGPT Desktop"

    def slug(self) -> str:
        return "chatgpt"

    def scan(self, show_secrets: bool = False) -> ScanResult:
        plat = detect_platform()
        result = ScanResult(scanner_name=self.name(), platform=plat.value)

        for path in self._get_config_paths(plat):
            self._scan_config_dir(path, result, show_secrets)

        return result

    def _get_config_paths(self, plat: Platform) -> list[Path]:
        paths = []

        if plat == Platform.MACOS:
            paths.append(get_home() / "Library" / "Application Support" / "ChatGPT")
            paths.append(get_home() / "Library" / "Application Support" / "com.openai.chat")

        elif plat == Platform.WINDOWS:
            appdata = get_appdata()
            if appdata:
                paths.append(appdata / "OpenAI" / "ChatGPT")
                paths.append(appdata / "com.openai.chat")

        elif plat == Platform.WSL:
            appdata = get_appdata()
            if appdata:
                paths.append(appdata / "OpenAI" / "ChatGPT")
                paths.append(appdata / "com.openai.chat")

        return paths

    def _scan_config_dir(
        self, base_path: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        if not base_path.exists():
            return

        # Look for any JSON files that might contain tokens
        for json_file in base_path.glob("*.json"):
            perms = get_file_permissions(json_file)
            owner = get_file_owner(json_file)

            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue

            if isinstance(data, dict):
                self._extract_tokens(data, json_file, perms, owner, result, show_secrets)

    def _extract_tokens(
        self, data: dict, path: Path, perms, owner, result: ScanResult, show_secrets: bool
    ) -> None:
        token_keys = [
            "accessToken", "access_token", "token", "session_token",
            "refresh_token", "api_key", "apiKey",
        ]
        for key in token_keys:
            value = data.get(key)
            if value and isinstance(value, str) and len(value) > 8:
                storage = StorageType.PLAINTEXT_JSON
                result.findings.append(CredentialFinding(
                    tool_name=self.name(),
                    credential_type=key,
                    storage_type=storage,
                    location=str(path),
                    exists=True,
                    risk_level=assess_risk(storage, path),
                    value_preview=mask_value(value, show_full=show_secrets),
                    raw_value=value if show_secrets else None,
                    file_permissions=perms,
                    file_owner=owner,
                ))

        # Recurse into nested objects
        for key, val in data.items():
            if isinstance(val, dict):
                self._extract_tokens(val, path, perms, owner, result, show_secrets)
