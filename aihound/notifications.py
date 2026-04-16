"""Cross-platform OS-native desktop notifications.

Dispatches to the right backend based on detected platform:
- Linux / WSL (if D-Bus reachable): `notify-send`
- macOS: `osascript`
- Windows: PowerShell (BurntToast if installed, else built-in toast XML)

All backends shell out via stdlib `subprocess`. No new Python dependencies.
If the OS backend is unavailable (e.g., no `notify-send` installed), we log a
warning on first use and all subsequent calls are no-ops.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from typing import Optional

from aihound.core.platform import detect_platform, Platform

logger = logging.getLogger("aihound.notifications")

# Urgency levels — Linux notify-send values; other backends map these as best they can
URGENCY_LOW = "low"
URGENCY_NORMAL = "normal"
URGENCY_CRITICAL = "critical"

_capability_checked = False
_capability_available = False


def _check_capability() -> bool:
    """Test whether the current platform can actually send notifications.

    Cached after first call.
    """
    global _capability_checked, _capability_available
    if _capability_checked:
        return _capability_available
    _capability_checked = True

    plat = detect_platform()
    if plat == Platform.LINUX or plat == Platform.WSL:
        _capability_available = shutil.which("notify-send") is not None
        if not _capability_available:
            logger.warning(
                "Desktop notifications unavailable: `notify-send` not found. "
                "Install libnotify-bin (apt) / libnotify (dnf) / equivalent to enable."
            )
    elif plat == Platform.MACOS:
        _capability_available = shutil.which("osascript") is not None
        if not _capability_available:
            logger.warning("Desktop notifications unavailable: `osascript` not found.")
    elif plat == Platform.WINDOWS:
        _capability_available = shutil.which("powershell.exe") is not None or shutil.which("powershell") is not None
        if not _capability_available:
            logger.warning("Desktop notifications unavailable: PowerShell not found.")
    else:
        _capability_available = False

    return _capability_available


def send_notification(
    title: str,
    body: str,
    urgency: str = URGENCY_NORMAL,
    icon: Optional[str] = None,
) -> bool:
    """Send a desktop notification. Returns True on success, False on failure.

    Non-fatal — if the backend is unavailable or the command fails, logs a debug
    message and returns False. Never raises.
    """
    if not _check_capability():
        return False

    plat = detect_platform()
    try:
        if plat == Platform.LINUX or plat == Platform.WSL:
            return _notify_linux(title, body, urgency, icon)
        if plat == Platform.MACOS:
            return _notify_macos(title, body, urgency)
        if plat == Platform.WINDOWS:
            return _notify_windows(title, body, urgency)
    except Exception as e:
        logger.debug("Notification backend raised: %s", e)
        return False

    return False


def _notify_linux(title: str, body: str, urgency: str, icon: Optional[str]) -> bool:
    cmd = ["notify-send", "--urgency=" + urgency, "--app-name=AIHound"]
    if icon:
        cmd.append(f"--icon={icon}")
    cmd.extend([title, body])
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    if result.returncode != 0:
        logger.debug("notify-send failed (rc=%d): %s", result.returncode, result.stderr)
        return False
    return True


def _notify_macos(title: str, body: str, urgency: str) -> bool:
    # osascript: display notification "<body>" with title "AIHound" subtitle "<title>"
    # Escape double quotes in user content
    safe_title = title.replace('"', '\\"')
    safe_body = body.replace('"', '\\"')
    script = (
        f'display notification "{safe_body}" with title "AIHound" '
        f'subtitle "{safe_title}"'
    )
    # Critical urgency: play a sound
    if urgency == URGENCY_CRITICAL:
        script += ' sound name "Basso"'
    result = subprocess.run(
        ["osascript", "-e", script], capture_output=True, text=True, timeout=5
    )
    if result.returncode != 0:
        logger.debug("osascript failed (rc=%d): %s", result.returncode, result.stderr)
        return False
    return True


def _notify_windows(title: str, body: str, urgency: str) -> bool:
    """Show a Windows toast via PowerShell.

    Uses Windows.UI.Notifications APIs that ship with Windows 10+. No external
    PowerShell modules required.
    """
    # Escape single quotes (PowerShell literal strings use doubled single quotes)
    safe_title = title.replace("'", "''")
    safe_body = body.replace("'", "''")

    # XML toast template — kept simple, uses the default AIHound app display name
    ps_script = f"""
$ErrorActionPreference = 'Stop'
[void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime]
$template = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>{safe_title}</text>
      <text>{safe_body}</text>
    </binding>
  </visual>
</toast>
"@
$xml = [Windows.Data.Xml.Dom.XmlDocument]::new()
$xml.LoadXml($template)
$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('AIHound')
$notifier.Show($toast)
""".strip()

    exe = shutil.which("powershell.exe") or shutil.which("powershell")
    if exe is None:
        return False
    result = subprocess.run(
        [exe, "-NoProfile", "-NonInteractive", "-Command", ps_script],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        logger.debug("PowerShell toast failed (rc=%d): %s", result.returncode, result.stderr)
        return False
    return True
