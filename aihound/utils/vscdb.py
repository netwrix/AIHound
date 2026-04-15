"""VS Code state.vscdb SQLite reader.

VS Code stores extension secrets in a SQLite database (state.vscdb)
encrypted with Electron's safeStorage API (AES-128-CBC).
We can detect the presence of stored secrets but cannot decrypt them
without the OS keychain encryption key.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Optional

from aihound.core.platform import (
    detect_platform, Platform, get_home, get_appdata, get_xdg_config,
)


def get_vscdb_paths() -> list[Path]:
    """Get possible paths to VS Code's state.vscdb file."""
    plat = detect_platform()
    paths = []

    if plat in (Platform.LINUX, Platform.WSL):
        paths.append(get_xdg_config() / "Code" / "User" / "globalStorage" / "state.vscdb")
    elif plat == Platform.MACOS:
        paths.append(
            get_home() / "Library" / "Application Support" / "Code"
            / "User" / "globalStorage" / "state.vscdb"
        )
    elif plat == Platform.WINDOWS:
        appdata = get_appdata()
        if appdata:
            paths.append(appdata / "Code" / "User" / "globalStorage" / "state.vscdb")

    if plat == Platform.WSL:
        appdata = get_appdata()
        if appdata:
            paths.append(appdata / "Code" / "User" / "globalStorage" / "state.vscdb")

    return paths


def list_secret_keys(vscdb_path: Path) -> list[str]:
    """List keys in the VS Code secret storage.

    Returns key names that have stored secrets (values are encrypted).
    """
    if not vscdb_path.exists():
        return []

    try:
        conn = sqlite3.connect(str(vscdb_path))
        cursor = conn.cursor()

        # The secrets are stored in the ItemTable with keys like:
        # secret://<publisher>.<extension>/<secret-name>
        cursor.execute(
            "SELECT key FROM ItemTable WHERE key LIKE 'secret://%'"
        )
        keys = [row[0] for row in cursor.fetchall()]
        conn.close()
        return keys

    except (sqlite3.Error, OSError):
        return []


def get_extension_ids_with_secrets(vscdb_path: Path) -> list[str]:
    """Get unique extension IDs that have stored secrets."""
    keys = list_secret_keys(vscdb_path)
    extensions = set()
    for key in keys:
        # Format: secret://<extension-id>/<secret-name>
        if key.startswith("secret://"):
            parts = key[len("secret://"):].split("/", 1)
            if parts:
                extensions.add(parts[0])
    return sorted(extensions)
