"""Scanner for Cline VS Code extension credentials."""

from __future__ import annotations

from pathlib import Path

from aihound.core.scanner import BaseScanner, ScanResult
from aihound.core.platform import (
    detect_platform, Platform, get_home, get_appdata, get_wsl_windows_home,
    get_xdg_config,
)
from aihound.core.mcp import parse_mcp_file
from aihound.scanners import register


@register
class ClineScanner(BaseScanner):
    def name(self) -> str:
        return "Cline (VS Code)"

    def slug(self) -> str:
        return "cline"

    def scan(self, show_secrets: bool = False) -> ScanResult:
        plat = detect_platform()
        result = ScanResult(scanner_name=self.name(), platform=plat.value)

        for path in self._get_mcp_settings_paths(plat):
            findings, errors = parse_mcp_file(path, self.name(), show_secrets)
            result.findings.extend(findings)
            result.errors.extend(errors)

        return result

    def _get_mcp_settings_paths(self, plat: Platform) -> list[Path]:
        """Cline stores MCP settings in VS Code globalStorage as plaintext JSON."""
        paths = []
        extension_id = "saoudrizwan.claude-dev"
        settings_file = "settings/cline_mcp_settings.json"

        if plat == Platform.MACOS:
            base = (
                get_home() / "Library" / "Application Support" / "Code"
                / "User" / "globalStorage" / extension_id
            )
            paths.append(base / settings_file)

        elif plat == Platform.WINDOWS:
            appdata = get_appdata()
            if appdata:
                base = appdata / "Code" / "User" / "globalStorage" / extension_id
                paths.append(base / settings_file)

        elif plat in (Platform.LINUX, Platform.WSL):
            base = get_xdg_config() / "Code" / "User" / "globalStorage" / extension_id
            paths.append(base / settings_file)

        if plat == Platform.WSL:
            appdata = get_appdata()
            if appdata:
                base = appdata / "Code" / "User" / "globalStorage" / extension_id
                paths.append(base / settings_file)

        return paths
