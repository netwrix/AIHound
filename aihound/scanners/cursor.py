"""Scanner for Cursor IDE credentials."""

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
class CursorScanner(BaseScanner):
    def name(self) -> str:
        return "Cursor IDE"

    def slug(self) -> str:
        return "cursor"

    def scan(self, show_secrets: bool = False) -> ScanResult:
        plat = detect_platform()
        result = ScanResult(scanner_name=self.name(), platform=plat.value)

        for path in self._get_mcp_paths(plat):
            findings, errors = parse_mcp_file(path, self.name(), show_secrets)
            result.findings.extend(findings)
            result.errors.extend(errors)

        return result

    def _get_mcp_paths(self, plat: Platform) -> list[Path]:
        paths = []
        home = get_home()

        # ~/.cursor/mcp.json
        paths.append(home / ".cursor" / "mcp.json")

        if plat == Platform.MACOS:
            paths.append(
                home / "Library" / "Application Support" / "Cursor" / "User"
                / "globalStorage" / "mcp.json"
            )
        elif plat == Platform.WINDOWS:
            appdata = get_appdata()
            if appdata:
                paths.append(appdata / "Cursor" / "User" / "globalStorage" / "mcp.json")
        elif plat in (Platform.LINUX, Platform.WSL):
            paths.append(get_xdg_config() / "Cursor" / "User" / "globalStorage" / "mcp.json")

        if plat == Platform.WSL:
            win_home = get_wsl_windows_home()
            if win_home:
                paths.append(win_home / ".cursor" / "mcp.json")
            appdata = get_appdata()
            if appdata:
                paths.append(appdata / "Cursor" / "User" / "globalStorage" / "mcp.json")

        return paths
