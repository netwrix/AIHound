"""Platform detection and path resolution."""

from __future__ import annotations

import os
import platform as _platform
from enum import Enum
from pathlib import Path
from typing import Optional


class Platform(Enum):
    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"
    WSL = "wsl"


_cached_platform: Optional[Platform] = None


def detect_platform() -> Platform:
    """Detect current OS. Distinguishes WSL from native Linux."""
    global _cached_platform
    if _cached_platform is not None:
        return _cached_platform

    system = _platform.system().lower()
    if system == "windows":
        _cached_platform = Platform.WINDOWS
    elif system == "darwin":
        _cached_platform = Platform.MACOS
    elif system == "linux":
        try:
            with open("/proc/version") as f:
                if "microsoft" in f.read().lower():
                    _cached_platform = Platform.WSL
                else:
                    _cached_platform = Platform.LINUX
        except (FileNotFoundError, PermissionError):
            _cached_platform = Platform.LINUX
    else:
        _cached_platform = Platform.LINUX

    return _cached_platform


def get_home() -> Path:
    """Get the user's home directory."""
    return Path.home()


def get_appdata() -> Optional[Path]:
    """Get Windows %APPDATA% path. Works on Windows and WSL."""
    plat = detect_platform()

    if plat == Platform.WINDOWS:
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata)
        return Path.home() / "AppData" / "Roaming"

    if plat == Platform.WSL:
        # Try to find Windows AppData via /mnt/c/Users/<user>/AppData/Roaming
        return _find_wsl_appdata()

    return None


def get_localappdata() -> Optional[Path]:
    """Get Windows %LOCALAPPDATA% path. Works on Windows and WSL."""
    plat = detect_platform()

    if plat == Platform.WINDOWS:
        localappdata = os.environ.get("LOCALAPPDATA")
        if localappdata:
            return Path(localappdata)
        return Path.home() / "AppData" / "Local"

    if plat == Platform.WSL:
        appdata = _find_wsl_appdata()
        if appdata:
            return appdata.parent / "Local"

    return None


def _find_wsl_appdata() -> Optional[Path]:
    """Find Windows AppData/Roaming from WSL via /mnt/c/Users/."""
    mnt_c = Path("/mnt/c/Users")
    if not mnt_c.exists():
        return None

    # Try to detect the Windows username from the WSL mount
    # Check common indicators
    for candidate in mnt_c.iterdir():
        if candidate.name in ("Public", "Default", "Default User", "All Users"):
            continue
        appdata = candidate / "AppData" / "Roaming"
        if appdata.exists():
            return appdata

    return None


def get_wsl_windows_home() -> Optional[Path]:
    """Get the Windows user home directory when running under WSL."""
    if detect_platform() != Platform.WSL:
        return None

    mnt_c = Path("/mnt/c/Users")
    if not mnt_c.exists():
        return None

    for candidate in mnt_c.iterdir():
        if candidate.name in ("Public", "Default", "Default User", "All Users"):
            continue
        if (candidate / "AppData").exists():
            return candidate

    return None


def get_xdg_config() -> Path:
    """Get XDG_CONFIG_HOME, defaulting to ~/.config."""
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))


def resolve_paths_for_tool(
    linux_paths: list[str | Path] = [],
    macos_paths: list[str | Path] = [],
    windows_paths: list[str | Path] = [],
) -> list[Path]:
    """Resolve paths based on current platform. On WSL, includes both Linux and Windows paths."""
    plat = detect_platform()
    paths: list[Path] = []

    if plat == Platform.LINUX:
        paths = [Path(p).expanduser() for p in linux_paths]
    elif plat == Platform.MACOS:
        paths = [Path(p).expanduser() for p in macos_paths]
    elif plat == Platform.WINDOWS:
        resolved = []
        for p in windows_paths:
            s = str(p)
            s = s.replace("%APPDATA%", str(get_appdata() or ""))
            s = s.replace("%LOCALAPPDATA%", str(get_localappdata() or ""))
            s = s.replace("%USERPROFILE%", str(Path.home()))
            resolved.append(Path(s))
        paths = resolved
    elif plat == Platform.WSL:
        # Scan Linux-native paths
        paths = [Path(p).expanduser() for p in linux_paths]
        # Also scan Windows paths via /mnt/c
        appdata = get_appdata()
        localappdata = get_localappdata()
        win_home = get_wsl_windows_home()
        for p in windows_paths:
            s = str(p)
            if appdata:
                s = s.replace("%APPDATA%", str(appdata))
            if localappdata:
                s = s.replace("%LOCALAPPDATA%", str(localappdata))
            if win_home:
                s = s.replace("%USERPROFILE%", str(win_home))
            if "%APPDATA%" not in s and "%LOCALAPPDATA%" not in s and "%USERPROFILE%" not in s:
                paths.append(Path(s))

    return paths
