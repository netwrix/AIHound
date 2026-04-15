"""Scanner for GitHub Copilot credentials."""

from __future__ import annotations

import json
from pathlib import Path

from aihound.core.scanner import (
    BaseScanner, CredentialFinding, ScanResult, StorageType, RiskLevel,
)
from aihound.core.platform import (
    detect_platform, Platform, get_home, get_appdata, get_wsl_windows_home,
    get_xdg_config,
)
from aihound.core.redactor import mask_value
from aihound.core.permissions import get_file_permissions, get_file_owner, assess_risk
from aihound.scanners import register


@register
class GitHubCopilotScanner(BaseScanner):
    def name(self) -> str:
        return "GitHub Copilot"

    def slug(self) -> str:
        return "github-copilot"

    def scan(self, show_secrets: bool = False) -> ScanResult:
        plat = detect_platform()
        result = ScanResult(scanner_name=self.name(), platform=plat.value)

        # Check copilot CLI config (plaintext fallback on Linux)
        for path in self._get_copilot_config_paths(plat):
            self._scan_copilot_config(path, result, show_secrets)

        # Check VS Code extension storage (hosts.json / apps.json)
        for path in self._get_vscode_copilot_paths(plat):
            self._scan_copilot_config(path, result, show_secrets)

        return result

    def _get_copilot_config_paths(self, plat: Platform) -> list[Path]:
        paths = []
        home = get_home()

        # ~/.copilot/config.json (Linux plaintext fallback)
        paths.append(home / ".copilot" / "config.json")

        # GitHub CLI auth config (gh stores tokens here)
        if plat in (Platform.LINUX, Platform.WSL):
            paths.append(get_xdg_config() / "gh" / "hosts.yml")
        elif plat == Platform.MACOS:
            paths.append(home / "Library" / "Application Support" / "gh" / "hosts.yml")
        elif plat == Platform.WINDOWS:
            appdata = get_appdata()
            if appdata:
                paths.append(appdata / "GitHub CLI" / "hosts.yml")

        if plat == Platform.WSL:
            win_home = get_wsl_windows_home()
            if win_home:
                paths.append(win_home / ".copilot" / "config.json")
            appdata = get_appdata()
            if appdata:
                paths.append(appdata / "GitHub CLI" / "hosts.yml")

        return paths

    def _get_vscode_copilot_paths(self, plat: Platform) -> list[Path]:
        """VS Code stores Copilot auth in globalStorage."""
        paths = []

        if plat in (Platform.LINUX, Platform.WSL):
            paths.append(
                get_xdg_config() / "Code" / "User" / "globalStorage"
                / "github.copilot" / "hosts.json"
            )
            paths.append(
                get_xdg_config() / "Code" / "User" / "globalStorage"
                / "github.copilot-chat" / "hosts.json"
            )
        elif plat == Platform.MACOS:
            base = get_home() / "Library" / "Application Support" / "Code" / "User" / "globalStorage"
            paths.append(base / "github.copilot" / "hosts.json")
            paths.append(base / "github.copilot-chat" / "hosts.json")
        elif plat == Platform.WINDOWS:
            appdata = get_appdata()
            if appdata:
                base = appdata / "Code" / "User" / "globalStorage"
                paths.append(base / "github.copilot" / "hosts.json")
                paths.append(base / "github.copilot-chat" / "hosts.json")

        if plat == Platform.WSL:
            appdata = get_appdata()
            if appdata:
                base = appdata / "Code" / "User" / "globalStorage"
                paths.append(base / "github.copilot" / "hosts.json")
                paths.append(base / "github.copilot-chat" / "hosts.json")

        return paths

    def _scan_copilot_config(
        self, path: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        if not path.exists():
            return

        perms = get_file_permissions(path)
        owner = get_file_owner(path)

        try:
            content = path.read_text(encoding="utf-8")
        except OSError as e:
            result.errors.append(f"Failed to read {path}: {e}")
            return

        # Try JSON
        try:
            data = json.loads(content)
            self._extract_tokens_from_json(data, path, perms, owner, result, show_secrets)
            return
        except json.JSONDecodeError:
            pass

        # Try YAML-like (simple key: value parsing for hosts.yml)
        self._extract_tokens_from_yaml_simple(content, path, perms, owner, result, show_secrets)

    def _extract_tokens_from_json(
        self, data, path, perms, owner, result, show_secrets
    ) -> None:
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, str) and len(value) > 10:
                    if any(k in key.lower() for k in ["token", "oauth", "key"]):
                        storage = StorageType.PLAINTEXT_JSON
                        result.findings.append(CredentialFinding(
                            tool_name=self.name(),
                            credential_type=f"copilot:{key}",
                            storage_type=storage,
                            location=str(path),
                            exists=True,
                            risk_level=assess_risk(storage, path),
                            value_preview=mask_value(value, show_full=show_secrets),
                            raw_value=value if show_secrets else None,
                            file_permissions=perms,
                            file_owner=owner,
                        ))
                elif isinstance(value, dict):
                    self._extract_tokens_from_json(value, path, perms, owner, result, show_secrets)

    def _extract_tokens_from_yaml_simple(
        self, content, path, perms, owner, result, show_secrets
    ) -> None:
        """Simple YAML parser for GitHub CLI hosts.yml oauth_token fields."""
        for line in content.splitlines():
            stripped = line.strip()
            if ":" in stripped:
                key, _, value = stripped.partition(":")
                key = key.strip()
                value = value.strip()
                if key.lower() in ("oauth_token", "token") and value:
                    storage = StorageType.PLAINTEXT_YAML
                    result.findings.append(CredentialFinding(
                        tool_name=self.name(),
                        credential_type=f"gh_cli:{key}",
                        storage_type=storage,
                        location=str(path),
                        exists=True,
                        risk_level=assess_risk(storage, path),
                        value_preview=mask_value(value, show_full=show_secrets),
                        raw_value=value if show_secrets else None,
                        file_permissions=perms,
                        file_owner=owner,
                        notes=["GitHub CLI auth config"],
                    ))
