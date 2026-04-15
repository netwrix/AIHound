"""Scanner for Claude Desktop application credentials."""

from __future__ import annotations

from pathlib import Path

from aihound.core.scanner import BaseScanner, ScanResult
from aihound.core.platform import (
    detect_platform, Platform, get_home, get_appdata, get_wsl_windows_home,
)
from aihound.core.mcp import parse_mcp_file
from aihound.scanners import register


@register
class ClaudeDesktopScanner(BaseScanner):
    def name(self) -> str:
        return "Claude Desktop"

    def slug(self) -> str:
        return "claude-desktop"

    def scan(self, show_secrets: bool = False) -> ScanResult:
        plat = detect_platform()
        result = ScanResult(scanner_name=self.name(), platform=plat.value)

        for path in self._get_config_paths(plat):
            findings, errors = parse_mcp_file(path, self.name(), show_secrets)
            result.findings.extend(findings)
            result.errors.extend(errors)

        return result

    def _get_config_paths(self, plat: Platform) -> list[Path]:
        paths = []

        if plat == Platform.MACOS:
            paths.append(
                get_home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
            )

        elif plat == Platform.WINDOWS:
            appdata = get_appdata()
            if appdata:
                paths.append(appdata / "Claude" / "claude_desktop_config.json")

        elif plat == Platform.LINUX:
            from aihound.core.platform import get_xdg_config
            paths.append(get_xdg_config() / "Claude" / "claude_desktop_config.json")

        elif plat == Platform.WSL:
            # Linux-side
            from aihound.core.platform import get_xdg_config
            paths.append(get_xdg_config() / "Claude" / "claude_desktop_config.json")
            # Windows-side
            appdata = get_appdata()
            if appdata:
                paths.append(appdata / "Claude" / "claude_desktop_config.json")

        return paths
