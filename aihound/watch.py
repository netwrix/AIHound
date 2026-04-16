"""Watch/monitor mode: continuous scanning with event-based alerting.

Re-runs all scanners on a configurable interval, diffs findings against the
previous snapshot, and emits events when credentials appear, disappear, change,
or become more dangerous.

Target audience: individual developers who want ongoing hygiene monitoring.
"""

from __future__ import annotations

import logging
import signal
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Iterable, Optional

from aihound.core.scanner import BaseScanner, CredentialFinding, RiskLevel, ScanResult

logger = logging.getLogger("aihound.watch")


class EventType(Enum):
    BASELINE = "baseline"            # Existing finding on first scan (no "new" implication)
    NEW = "new"                      # Credential appeared since last scan
    REMOVED = "removed"              # Credential gone since last scan
    PERMISSION_CHANGED = "permission_changed"
    CONTENT_CHANGED = "content_changed"
    RISK_ESCALATED = "risk_escalated"
    NETWORK_EXPOSED = "network_exposed"


# Network-exposure scanners whose NEW events are re-classified as NETWORK_EXPOSED
# for richer operator-facing alerting.
_NETWORK_SCANNERS = {"Ollama", "LM Studio", "AI Network Exposure"}


@dataclass
class WatchEvent:
    """One change detected by the watch loop."""
    event_type: EventType
    timestamp: datetime
    finding: CredentialFinding
    # Only populated for PERMISSION_CHANGED / CONTENT_CHANGED / RISK_ESCALATED
    previous_finding: Optional[CredentialFinding] = None

    def to_dict(self) -> dict:
        d = {
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "finding": self.finding.to_dict(),
        }
        if self.previous_finding is not None:
            d["previous_finding"] = self.previous_finding.to_dict()
        return d


# Stable-key type alias
FindingKey = tuple[str, str, str]


def finding_key(f: CredentialFinding) -> FindingKey:
    """Produce a stable dedup key for a finding.

    Uses (tool_name, credential_type, location). For most scanners `location` is a
    file path; for the powershell scanner it includes a ":line_number" suffix
    which correctly identifies distinct credentials in the same history file.
    """
    return (f.tool_name, f.credential_type, f.location)


_RISK_ORDER = {
    RiskLevel.INFO: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}


def risk_at_or_above(finding_risk: RiskLevel, min_risk: RiskLevel) -> bool:
    """True if finding_risk is >= min_risk in severity."""
    return _RISK_ORDER.get(finding_risk, 0) >= _RISK_ORDER.get(min_risk, 0)


def flatten_to_dict(results: Iterable[ScanResult]) -> dict[FindingKey, CredentialFinding]:
    """Flatten a list of ScanResults into a dict keyed by finding_key."""
    out: dict[FindingKey, CredentialFinding] = {}
    for r in results:
        for f in r.findings:
            out[finding_key(f)] = f
    return out


def diff_findings(
    old: dict[FindingKey, CredentialFinding],
    new: dict[FindingKey, CredentialFinding],
    now: Optional[datetime] = None,
) -> list[WatchEvent]:
    """Return ordered list of WatchEvents describing the delta from old -> new."""
    if now is None:
        now = datetime.now(timezone.utc)

    events: list[WatchEvent] = []
    old_keys = set(old.keys())
    new_keys = set(new.keys())

    # NEW findings
    for key in new_keys - old_keys:
        finding = new[key]
        # Re-classify network-exposure NEW events as NETWORK_EXPOSED when relevant
        if finding.tool_name in _NETWORK_SCANNERS and finding.risk_level == RiskLevel.CRITICAL:
            events.append(WatchEvent(EventType.NETWORK_EXPOSED, now, finding))
        else:
            events.append(WatchEvent(EventType.NEW, now, finding))

    # REMOVED findings
    for key in old_keys - new_keys:
        events.append(WatchEvent(EventType.REMOVED, now, old[key]))

    # CHANGED findings (intersection of keys)
    for key in new_keys & old_keys:
        old_f = old[key]
        new_f = new[key]

        perm_changed = (old_f.file_permissions or "") != (new_f.file_permissions or "")
        content_changed = (
            (old_f.file_modified or None) != (new_f.file_modified or None)
            or (old_f.value_preview or "") != (new_f.value_preview or "")
        )
        risk_escalated = (
            _RISK_ORDER.get(new_f.risk_level, 0) > _RISK_ORDER.get(old_f.risk_level, 0)
        )

        if perm_changed:
            events.append(WatchEvent(EventType.PERMISSION_CHANGED, now, new_f, old_f))
        elif content_changed:
            # Emit CONTENT_CHANGED only if no PERMISSION_CHANGED already covered this key
            events.append(WatchEvent(EventType.CONTENT_CHANGED, now, new_f, old_f))

        if risk_escalated:
            events.append(WatchEvent(EventType.RISK_ESCALATED, now, new_f, old_f))

    return events


class DebounceTracker:
    """Suppress duplicate (key, event_type) events within a time window."""

    def __init__(self, window_seconds: float = 10.0):
        self.window = window_seconds
        self._last_emit: dict[tuple[FindingKey, EventType], float] = {}

    def allow(self, event: WatchEvent, now: Optional[float] = None) -> bool:
        if self.window <= 0:
            return True
        if now is None:
            now = time.monotonic()
        key = (finding_key(event.finding), event.event_type)
        last = self._last_emit.get(key)
        if last is None or (now - last) >= self.window:
            self._last_emit[key] = now
            return True
        return False


def filter_events(
    events: list[WatchEvent], min_risk: RiskLevel
) -> list[WatchEvent]:
    """Drop events whose finding.risk_level is below min_risk.

    REMOVED events are kept regardless of severity — they always indicate a state
    change worth knowing about.
    """
    out: list[WatchEvent] = []
    for ev in events:
        if ev.event_type == EventType.REMOVED:
            out.append(ev)
            continue
        if risk_at_or_above(ev.finding.risk_level, min_risk):
            out.append(ev)
    return out


# Sink protocol: any callable that takes a WatchEvent
EventSink = Callable[[WatchEvent], None]


class WatchLoop:
    """Main watch/monitor loop.

    Call `run()` to block until SIGINT/SIGTERM. Scans on each interval, diffs
    against the previous snapshot, filters by min_risk, debounces, and fans out
    events to all registered sinks.
    """

    def __init__(
        self,
        scanners: list[BaseScanner],
        sinks: list[EventSink],
        interval: float = 30.0,
        min_risk: RiskLevel = RiskLevel.INFO,
        debounce_seconds: float = 10.0,
        show_secrets: bool = False,
    ):
        self.scanners = scanners
        self.sinks = sinks
        self.interval = interval
        self.min_risk = min_risk
        self.debounce = DebounceTracker(debounce_seconds)
        self.show_secrets = show_secrets

        self._stop = False
        self._event_count = 0
        self._started_at: Optional[float] = None

    def _handle_signal(self, signum, _frame):
        logger.debug("Received signal %d, stopping watch loop", signum)
        self._stop = True

    def _emit(self, event: WatchEvent) -> None:
        if not self.debounce.allow(event):
            logger.debug(
                "Debounced %s event for %s",
                event.event_type.value,
                finding_key(event.finding),
            )
            return
        self._event_count += 1
        for sink in self.sinks:
            try:
                sink(event)
            except Exception as e:
                logger.warning("Sink raised %s: %s", type(e).__name__, e)

    def _scan_once(self) -> list[ScanResult]:
        results: list[ScanResult] = []
        for scanner in self.scanners:
            logger.debug("Scanning: %s", scanner.name())
            result = scanner.run(show_secrets=self.show_secrets)
            results.append(result)
        return results

    def run(self) -> int:
        """Main loop. Returns total event count on clean exit."""
        # Install signal handlers (only on main thread)
        try:
            signal.signal(signal.SIGINT, self._handle_signal)
            signal.signal(signal.SIGTERM, self._handle_signal)
        except (ValueError, AttributeError):
            # Not the main thread, or platform doesn't support SIGTERM (Windows)
            pass

        self._started_at = time.monotonic()
        prev_state: dict[FindingKey, CredentialFinding] = {}
        first_run = True

        logger.info(
            "Watch mode starting: interval=%ds, scanners=%d, min_risk=%s",
            int(self.interval),
            len(self.scanners),
            self.min_risk.value,
        )

        while not self._stop:
            scan_start = time.monotonic()
            try:
                results = self._scan_once()
            except Exception as e:
                logger.error("Scan cycle failed: %s", e, exc_info=True)
                self._sleep(self.interval)
                continue

            curr_state = flatten_to_dict(results)
            now = datetime.now(timezone.utc)

            if first_run:
                # Emit every existing finding as a BASELINE event
                for f in curr_state.values():
                    if risk_at_or_above(f.risk_level, self.min_risk):
                        self._emit(WatchEvent(EventType.BASELINE, now, f))
                first_run = False
            else:
                events = diff_findings(prev_state, curr_state, now=now)
                events = filter_events(events, self.min_risk)
                for event in events:
                    self._emit(event)

            prev_state = curr_state

            elapsed = time.monotonic() - scan_start
            sleep_for = max(0.0, self.interval - elapsed)
            self._sleep(sleep_for)

        return self._event_count

    def _sleep(self, seconds: float) -> None:
        """Sleep in small chunks so stop signal is responsive."""
        end = time.monotonic() + seconds
        while not self._stop and time.monotonic() < end:
            time.sleep(min(0.5, end - time.monotonic()))
