"""File permission analysis."""

from __future__ import annotations

import datetime
import os
import stat
from pathlib import Path
from typing import Optional

from aihound.core.platform import detect_platform, Platform
from aihound.core.scanner import RiskLevel, StorageType


def get_file_permissions(path: Path) -> Optional[str]:
    """Get file permissions as an octal string (e.g., '0600')."""
    try:
        st = os.stat(path)
        mode = stat.S_IMODE(st.st_mode)
        return f"{mode:04o}"
    except (OSError, ValueError):
        return None


def get_file_owner(path: Path) -> Optional[str]:
    """Get the file owner username."""
    try:
        st = os.stat(path)
        plat = detect_platform()
        if plat in (Platform.LINUX, Platform.MACOS, Platform.WSL):
            import pwd
            try:
                return pwd.getpwuid(st.st_uid).pw_name
            except KeyError:
                return str(st.st_uid)
        return None
    except OSError:
        return None


def is_world_readable(path: Path) -> bool:
    """Check if a file is readable by others (o+r)."""
    try:
        st = os.stat(path)
        return bool(st.st_mode & stat.S_IROTH)
    except OSError:
        return False


def is_group_readable(path: Path) -> bool:
    """Check if a file is readable by group (g+r)."""
    try:
        st = os.stat(path)
        return bool(st.st_mode & stat.S_IRGRP)
    except OSError:
        return False


def describe_permissions(perms: Optional[str]) -> str:
    """Translate octal permission string to human-readable description.

    Examples:
        '0777' -> 'world-readable, world-writable (DANGEROUS)'
        '0644' -> 'world-readable'
        '0600' -> 'owner-only'
        '0640' -> 'group-readable'
    """
    if not perms:
        return "unknown"

    try:
        mode = int(perms, 8)
    except ValueError:
        return "unknown"

    parts = []

    # Owner
    owner_r = bool(mode & stat.S_IRUSR)
    owner_w = bool(mode & stat.S_IWUSR)
    owner_x = bool(mode & stat.S_IXUSR)

    # Group
    group_r = bool(mode & stat.S_IRGRP)
    group_w = bool(mode & stat.S_IWGRP)
    group_x = bool(mode & stat.S_IXGRP)

    # Other
    other_r = bool(mode & stat.S_IROTH)
    other_w = bool(mode & stat.S_IWOTH)
    other_x = bool(mode & stat.S_IXOTH)

    if other_w:
        parts.append("world-writable")
    if other_r:
        parts.append("world-readable")
    if other_x and not other_r and not other_w:
        parts.append("world-executable")

    if group_w and not other_w:
        parts.append("group-writable")
    if group_r and not other_r:
        parts.append("group-readable")

    if not group_r and not other_r:
        parts.append("owner-only")

    if other_w or (other_r and other_w):
        parts.append("DANGEROUS")

    return ", ".join(parts) if parts else "owner-only"


def assess_risk(storage_type: StorageType, path: Optional[Path] = None) -> RiskLevel:
    """Determine risk level based on storage type and file permissions."""
    if storage_type == StorageType.ENVIRONMENT_VAR:
        return RiskLevel.MEDIUM

    if storage_type in (StorageType.KEYCHAIN, StorageType.CREDENTIAL_MANAGER):
        return RiskLevel.MEDIUM

    if storage_type == StorageType.ENCRYPTED_DB:
        return RiskLevel.MEDIUM

    # Plaintext storage types
    if storage_type in (
        StorageType.PLAINTEXT_JSON,
        StorageType.PLAINTEXT_YAML,
        StorageType.PLAINTEXT_ENV,
        StorageType.PLAINTEXT_INI,
    ):
        if path and path.exists():
            if is_world_readable(path):
                return RiskLevel.CRITICAL
            if is_group_readable(path):
                return RiskLevel.HIGH
            return RiskLevel.HIGH
        return RiskLevel.HIGH

    return RiskLevel.INFO


def get_file_mtime(path) -> Optional[datetime.datetime]:
    """Return file modification time as UTC datetime, or None on error."""
    try:
        mtime = os.path.getmtime(str(path))
        return datetime.datetime.fromtimestamp(mtime, tz=datetime.timezone.utc)
    except (OSError, ValueError):
        return None


def describe_staleness(mtime: datetime.datetime) -> str:
    """Return human-readable staleness like '3 hours ago', '45 days ago'."""
    now = datetime.datetime.now(datetime.timezone.utc)
    delta = now - mtime
    seconds = delta.total_seconds()
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        mins = int(seconds // 60)
        return f"{mins} minute{'s' if mins != 1 else ''} ago"
    if seconds < 86400:
        hours = int(seconds // 3600)
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    days = int(seconds // 86400)
    if days < 365:
        return f"{days} day{'s' if days != 1 else ''} ago"
    years = days // 365
    return f"{years} year{'s' if years != 1 else ''} ago"
