"""Output sinks for watch mode events.

Three sinks:
- TerminalEventSink    — colored one-line output to stdout (or any TextIO)
- NDJSONEventSink      — one JSON object per line to stdout / file
- NotificationEventSink — OS-native desktop toasts (filtered by min-risk)

Each sink implements a single `__call__(event: WatchEvent)` method so it can be
registered as an EventSink in watch.WatchLoop.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, TextIO

from aihound.core.scanner import RiskLevel
from aihound.watch import EventType, WatchEvent, risk_at_or_above
from aihound.notifications import (
    URGENCY_CRITICAL,
    URGENCY_LOW,
    URGENCY_NORMAL,
    send_notification,
)

logger = logging.getLogger("aihound.watch.formatters")


# ANSI colors (matched to aihound/output/table.py palette)
_COLORS = {
    RiskLevel.CRITICAL: "\033[91m",  # red
    RiskLevel.HIGH: "\033[93m",      # yellow
    RiskLevel.MEDIUM: "\033[33m",    # orange-ish
    RiskLevel.LOW: "\033[92m",       # green
    RiskLevel.INFO: "\033[36m",      # cyan
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"

# Event-type labels — padded to the same width for column alignment
_EVENT_LABEL = {
    EventType.BASELINE: "BASELINE ",
    EventType.NEW: "NEW      ",
    EventType.REMOVED: "REMOVED  ",
    EventType.PERMISSION_CHANGED: "PERM+    ",
    EventType.CONTENT_CHANGED: "CHANGED  ",
    EventType.RISK_ESCALATED: "RISK+    ",
    EventType.NETWORK_EXPOSED: "NETWORK  ",
}

# Event-type colors — orthogonal to risk color, so operators can visually
# distinguish event class at a glance
_EVENT_COLOR = {
    EventType.BASELINE: "\033[90m",         # gray
    EventType.NEW: "\033[95m",              # magenta
    EventType.REMOVED: "\033[94m",          # blue
    EventType.PERMISSION_CHANGED: "\033[93m",  # yellow
    EventType.CONTENT_CHANGED: "\033[36m",  # cyan
    EventType.RISK_ESCALATED: "\033[91m",   # red
    EventType.NETWORK_EXPOSED: "\033[91m",  # red
}


def _fmt_time(ts: datetime) -> str:
    """Format a datetime as HH:MM:SS in local time for terminal display."""
    return ts.astimezone().strftime("%H:%M:%S")


def _truncate(s: str, width: int) -> str:
    if len(s) <= width:
        return s
    return s[: width - 3] + "..."


class TerminalEventSink:
    """Colored one-line output for interactive terminal use.

    Example:
        [10:42:17] NEW       CRITICAL  Claude Code CLI   oauth_access_token at ~/.claude/...
    """

    def __init__(self, file: TextIO = sys.stdout, no_color: bool = False):
        self.file = file
        self.no_color = no_color

    def _c(self, code: str) -> str:
        return "" if self.no_color else code

    def __call__(self, event: WatchEvent) -> None:
        f = event.finding
        risk = f.risk_level
        ts = _fmt_time(event.timestamp)

        event_label = _EVENT_LABEL[event.event_type]
        event_color = self._c(_EVENT_COLOR[event.event_type])
        risk_color = self._c(_COLORS.get(risk, ""))
        bold = self._c(_BOLD)
        dim = self._c(_DIM)
        reset = self._c(_RESET)

        line = (
            f"{dim}[{ts}]{reset} "
            f"{event_color}{event_label}{reset} "
            f"{risk_color}{bold}{risk.value.upper():<9}{reset} "
            f"{_truncate(f.tool_name, 20):<20} "
            f"{_truncate(f.credential_type, 24):<24} "
            f"{_truncate(f.location, 60)}"
        )
        print(line, file=self.file, flush=True)

        # For escalations, show the risk transition inline
        if event.event_type == EventType.RISK_ESCALATED and event.previous_finding:
            prev = event.previous_finding.risk_level.value.upper()
            now = risk.value.upper()
            print(f"            {dim}└─ Risk escalated: {prev} → {now}{reset}",
                  file=self.file, flush=True)

        # For perm changes, show the before/after permissions
        if event.event_type == EventType.PERMISSION_CHANGED and event.previous_finding:
            old_p = event.previous_finding.file_permissions or "?"
            new_p = f.file_permissions or "?"
            print(f"            {dim}└─ Permissions: {old_p} → {new_p}{reset}",
                  file=self.file, flush=True)


class NDJSONEventSink:
    """One JSON object per line, to stdout or a file.

    File writes open in append mode so multiple AIHound processes can share
    a single watch log safely-ish (each line is atomic on most filesystems).
    """

    def __init__(self, file: Optional[TextIO] = None, filepath: Optional[str] = None):
        if file is None and filepath is None:
            raise ValueError("NDJSONEventSink requires either file or filepath")
        self._owned = False
        if filepath is not None:
            path = Path(filepath).expanduser()
            if path.parent and not path.parent.exists():
                path.parent.mkdir(parents=True, exist_ok=True)
            self.file = open(path, "a", encoding="utf-8", buffering=1)
            self._owned = True
        else:
            self.file = file

    def __call__(self, event: WatchEvent) -> None:
        line = json.dumps(event.to_dict(), separators=(",", ":"))
        print(line, file=self.file, flush=True)

    def close(self) -> None:
        if self._owned and self.file is not None:
            try:
                self.file.close()
            except OSError:
                pass


class NotificationEventSink:
    """Fires OS-native desktop toasts for events at or above min-risk.

    BASELINE events never notify (would be a toast storm on startup).
    REMOVED events only notify at NORMAL urgency regardless of finding risk.
    """

    def __init__(self, min_risk: RiskLevel = RiskLevel.HIGH):
        self.min_risk = min_risk

    def __call__(self, event: WatchEvent) -> None:
        # Never notify on baseline — would be noisy on first run
        if event.event_type == EventType.BASELINE:
            return

        # Filter by min-risk (REMOVED keeps going through regardless of severity)
        if event.event_type != EventType.REMOVED:
            if not risk_at_or_above(event.finding.risk_level, self.min_risk):
                return

        f = event.finding
        risk = f.risk_level.value.upper()
        event_name = event.event_type.value.replace("_", " ").title()
        title = f"AIHound — {event_name} ({risk})"
        body = f"{f.tool_name}: {f.credential_type}\n{_truncate(f.location, 80)}"

        # Map risk level to urgency
        if f.risk_level == RiskLevel.CRITICAL:
            urgency = URGENCY_CRITICAL
        elif f.risk_level == RiskLevel.HIGH:
            urgency = URGENCY_NORMAL
        else:
            urgency = URGENCY_LOW

        send_notification(title, body, urgency=urgency)
