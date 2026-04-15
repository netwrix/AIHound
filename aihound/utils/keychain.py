"""macOS Keychain query utilities."""

from __future__ import annotations

import subprocess
from typing import Optional

from aihound.core.platform import detect_platform, Platform


def query_keychain(service: str) -> Optional[str]:
    """Query macOS Keychain for a credential by service name.

    Returns the password/token value if found, None otherwise.
    Only works on macOS.
    """
    if detect_platform() != Platform.MACOS:
        return None

    try:
        result = subprocess.run(
            [
                "security", "find-generic-password",
                "-s", service,
                "-w",  # Output only the password
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return None


def list_keychain_entries(service_filter: str = "") -> list[dict]:
    """List Keychain entries, optionally filtered by service name.

    Returns list of dicts with 'service', 'account' keys.
    Only works on macOS.
    """
    if detect_platform() != Platform.MACOS:
        return []

    try:
        result = subprocess.run(
            ["security", "dump-keychain"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return []

        entries = []
        current = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith('"svce"'):
                # Service name
                val = _extract_keychain_value(line)
                if val:
                    current["service"] = val
            elif line.startswith('"acct"'):
                val = _extract_keychain_value(line)
                if val:
                    current["account"] = val
            elif line == "attributes:":
                if current and (not service_filter or service_filter in current.get("service", "")):
                    entries.append(current)
                current = {}

        if current and (not service_filter or service_filter in current.get("service", "")):
            entries.append(current)

        return entries

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []


def _extract_keychain_value(line: str) -> Optional[str]:
    """Extract value from a Keychain dump line like '"svce"<blob>="My Service"'."""
    if '="' in line:
        _, _, val = line.partition('="')
        return val.rstrip('"')
    return None
