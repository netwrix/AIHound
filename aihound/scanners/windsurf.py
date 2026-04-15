"""Scanner for Windsurf (Codeium) credentials."""

from __future__ import annotations

import json
from pathlib import Path

from aihound.core.scanner import (
    BaseScanner, CredentialFinding, ScanResult, StorageType,
)
from aihound.core.platform import detect_platform, Platform, get_home, get_wsl_windows_home
from aihound.core.redactor import mask_value
from aihound.core.permissions import get_file_permissions, get_file_owner, assess_risk
from aihound.core.mcp import parse_mcp_file
from aihound.scanners import register


@register
class WindsurfScanner(BaseScanner):
    def name(self) -> str:
        return "Windsurf"

    def slug(self) -> str:
        return "windsurf"

    def scan(self, show_secrets: bool = False) -> ScanResult:
        plat = detect_platform()
        result = ScanResult(scanner_name=self.name(), platform=plat.value)

        for path in self._get_config_paths(plat):
            self._scan_config_dir(path, result, show_secrets)

        for path in self._get_mcp_paths(plat):
            findings, errors = parse_mcp_file(path, self.name(), show_secrets)
            result.findings.extend(findings)
            result.errors.extend(errors)

        return result

    def _get_config_paths(self, plat: Platform) -> list[Path]:
        paths = []
        home = get_home()

        paths.append(home / ".codeium" / "windsurf")

        if plat == Platform.WSL:
            win_home = get_wsl_windows_home()
            if win_home:
                paths.append(win_home / ".codeium" / "windsurf")

        return paths

    def _get_mcp_paths(self, plat: Platform) -> list[Path]:
        paths = []
        home = get_home()

        paths.append(home / ".codeium" / "windsurf" / "mcp_config.json")

        if plat == Platform.WSL:
            win_home = get_wsl_windows_home()
            if win_home:
                paths.append(win_home / ".codeium" / "windsurf" / "mcp_config.json")

        return paths

    def _scan_config_dir(
        self, base_path: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        if not base_path.exists():
            return

        # Look for auth/config files
        auth_files = [
            "config.json",
            "auth.json",
            "credentials.json",
        ]

        for fname in auth_files:
            path = base_path / fname
            if not path.exists():
                continue

            perms = get_file_permissions(path)
            owner = get_file_owner(path)

            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue

            if isinstance(data, dict):
                self._extract_tokens(data, path, perms, owner, result, show_secrets)

    def _extract_tokens(
        self, data: dict, path: Path, perms, owner, result: ScanResult, show_secrets: bool
    ) -> None:
        token_keys = ["api_key", "apiKey", "token", "auth_token", "access_token", "refresh_token"]
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
