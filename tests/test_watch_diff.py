"""Tests for watch mode diff engine, debouncing, and min-risk filtering."""

from __future__ import annotations

import datetime

from aihound.core.scanner import (
    CredentialFinding,
    RiskLevel,
    StorageType,
)
from aihound.watch import (
    DebounceTracker,
    EventType,
    WatchEvent,
    diff_findings,
    filter_events,
    finding_key,
    flatten_to_dict,
    risk_at_or_above,
)


def _mk(
    tool="Claude Code CLI",
    ctype="oauth_access_token",
    location="/tmp/foo.json",
    risk=RiskLevel.CRITICAL,
    perms="0600",
    mtime=None,
    preview="sk-ant-abc",
):
    return CredentialFinding(
        tool_name=tool,
        credential_type=ctype,
        storage_type=StorageType.PLAINTEXT_JSON,
        location=location,
        exists=True,
        risk_level=risk,
        value_preview=preview,
        file_permissions=perms,
        file_modified=mtime,
    )


class TestFindingKey:
    def test_key_is_stable_tuple(self):
        f1 = _mk()
        f2 = _mk()
        assert finding_key(f1) == finding_key(f2)

    def test_different_location_makes_different_key(self):
        assert finding_key(_mk(location="/a")) != finding_key(_mk(location="/b"))

    def test_different_tool_makes_different_key(self):
        assert finding_key(_mk(tool="A")) != finding_key(_mk(tool="B"))

    def test_different_credential_type_makes_different_key(self):
        assert finding_key(_mk(ctype="access")) != finding_key(_mk(ctype="refresh"))

    def test_powershell_line_in_location_makes_unique(self):
        f1 = _mk(tool="PowerShell Logs", location="/tmp/hist.txt:42")
        f2 = _mk(tool="PowerShell Logs", location="/tmp/hist.txt:99")
        assert finding_key(f1) != finding_key(f2)


class TestDiffFindings:
    def test_empty_diff(self):
        assert diff_findings({}, {}) == []

    def test_new_finding(self):
        f = _mk()
        events = diff_findings({}, {finding_key(f): f})
        assert len(events) == 1
        assert events[0].event_type == EventType.NEW
        assert events[0].finding == f

    def test_removed_finding(self):
        f = _mk()
        events = diff_findings({finding_key(f): f}, {})
        assert len(events) == 1
        assert events[0].event_type == EventType.REMOVED
        assert events[0].finding == f

    def test_permission_changed(self):
        old = _mk(perms="0600")
        new = _mk(perms="0644")
        events = diff_findings({finding_key(old): old}, {finding_key(new): new})
        event_types = {e.event_type for e in events}
        assert EventType.PERMISSION_CHANGED in event_types

    def test_permission_change_with_risk_escalation_emits_both(self):
        # 0600 → 0644 means risk goes HIGH → CRITICAL (world-readable)
        # The scanner would re-assess, but here we simulate the risk jump directly
        old = _mk(perms="0600", risk=RiskLevel.HIGH)
        new = _mk(perms="0644", risk=RiskLevel.CRITICAL)
        events = diff_findings({finding_key(old): old}, {finding_key(new): new})
        types = {e.event_type for e in events}
        assert EventType.PERMISSION_CHANGED in types
        assert EventType.RISK_ESCALATED in types

    def test_content_changed_via_mtime(self):
        t1 = datetime.datetime(2026, 4, 16, 10, tzinfo=datetime.timezone.utc)
        t2 = datetime.datetime(2026, 4, 16, 11, tzinfo=datetime.timezone.utc)
        old = _mk(mtime=t1, perms="0600")
        new = _mk(mtime=t2, perms="0600")
        events = diff_findings({finding_key(old): old}, {finding_key(new): new})
        types = {e.event_type for e in events}
        assert EventType.CONTENT_CHANGED in types
        assert EventType.PERMISSION_CHANGED not in types

    def test_content_changed_via_preview(self):
        old = _mk(preview="sk-ant-aaa")
        new = _mk(preview="sk-ant-bbb")
        events = diff_findings({finding_key(old): old}, {finding_key(new): new})
        assert any(e.event_type == EventType.CONTENT_CHANGED for e in events)

    def test_perm_change_suppresses_separate_content_change_event(self):
        # If both perm and content change, we only emit PERMISSION_CHANGED
        # (prevents duplicate events for the same state transition)
        t1 = datetime.datetime(2026, 4, 16, 10, tzinfo=datetime.timezone.utc)
        t2 = datetime.datetime(2026, 4, 16, 11, tzinfo=datetime.timezone.utc)
        old = _mk(perms="0600", mtime=t1)
        new = _mk(perms="0644", mtime=t2)
        events = diff_findings({finding_key(old): old}, {finding_key(new): new})
        types = [e.event_type for e in events]
        # Should have PERMISSION_CHANGED but NOT CONTENT_CHANGED
        assert EventType.PERMISSION_CHANGED in types
        assert EventType.CONTENT_CHANGED not in types

    def test_network_exposed_is_reclassified_from_new_for_network_scanners(self):
        f = _mk(tool="Ollama", ctype="network_exposure", risk=RiskLevel.CRITICAL)
        events = diff_findings({}, {finding_key(f): f})
        assert events[0].event_type == EventType.NETWORK_EXPOSED

    def test_unchanged_finding_emits_nothing(self):
        f = _mk()
        events = diff_findings({finding_key(f): f}, {finding_key(f): f})
        assert events == []


class TestFlattenToDict:
    def test_empty_results(self):
        assert flatten_to_dict([]) == {}

    def test_flattens_findings_from_multiple_results(self):
        from aihound.core.scanner import ScanResult
        r1 = ScanResult(scanner_name="a", platform="linux", findings=[_mk(location="/a")])
        r2 = ScanResult(scanner_name="b", platform="linux", findings=[_mk(location="/b")])
        out = flatten_to_dict([r1, r2])
        assert len(out) == 2


class TestRiskOrdering:
    def test_critical_at_or_above_high(self):
        assert risk_at_or_above(RiskLevel.CRITICAL, RiskLevel.HIGH)

    def test_high_at_or_above_high(self):
        assert risk_at_or_above(RiskLevel.HIGH, RiskLevel.HIGH)

    def test_medium_not_at_or_above_high(self):
        assert not risk_at_or_above(RiskLevel.MEDIUM, RiskLevel.HIGH)

    def test_info_at_or_above_info(self):
        assert risk_at_or_above(RiskLevel.INFO, RiskLevel.INFO)


class TestFilterEvents:
    def _ev(self, risk=RiskLevel.HIGH, event_type=EventType.NEW):
        return WatchEvent(
            event_type,
            datetime.datetime.now(datetime.timezone.utc),
            _mk(risk=risk),
        )

    def test_drops_below_threshold(self):
        evs = [self._ev(risk=RiskLevel.INFO), self._ev(risk=RiskLevel.HIGH)]
        out = filter_events(evs, min_risk=RiskLevel.HIGH)
        assert len(out) == 1

    def test_removed_always_kept(self):
        evs = [self._ev(risk=RiskLevel.INFO, event_type=EventType.REMOVED)]
        out = filter_events(evs, min_risk=RiskLevel.CRITICAL)
        assert len(out) == 1


class TestDebounceTracker:
    def test_first_event_always_allowed(self):
        t = DebounceTracker(10.0)
        ev = WatchEvent(EventType.NEW, datetime.datetime.now(datetime.timezone.utc), _mk())
        assert t.allow(ev, now=0.0)

    def test_duplicate_within_window_suppressed(self):
        t = DebounceTracker(10.0)
        ev = WatchEvent(EventType.NEW, datetime.datetime.now(datetime.timezone.utc), _mk())
        assert t.allow(ev, now=0.0)
        assert not t.allow(ev, now=5.0)

    def test_duplicate_after_window_allowed(self):
        t = DebounceTracker(10.0)
        ev = WatchEvent(EventType.NEW, datetime.datetime.now(datetime.timezone.utc), _mk())
        assert t.allow(ev, now=0.0)
        assert t.allow(ev, now=15.0)

    def test_different_event_types_not_deduped_against_each_other(self):
        t = DebounceTracker(10.0)
        f = _mk()
        e1 = WatchEvent(EventType.NEW, datetime.datetime.now(datetime.timezone.utc), f)
        e2 = WatchEvent(EventType.CONTENT_CHANGED, datetime.datetime.now(datetime.timezone.utc), f)
        assert t.allow(e1, now=0.0)
        assert t.allow(e2, now=1.0)

    def test_window_zero_disables_debouncing(self):
        t = DebounceTracker(0.0)
        ev = WatchEvent(EventType.NEW, datetime.datetime.now(datetime.timezone.utc), _mk())
        assert t.allow(ev, now=0.0)
        assert t.allow(ev, now=0.1)
