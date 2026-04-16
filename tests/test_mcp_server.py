"""Tests for the MCP server: serialization, cache, tool handler behavior.

These tests exercise the module's internal helpers directly — they do NOT spin
up a full MCP stdio server (that's covered by the end-to-end smoke tests).
Running these tests does NOT require the `mcp` SDK.
"""

from __future__ import annotations

import time
from unittest import mock

import pytest

from aihound.core.scanner import (
    CredentialFinding,
    RiskLevel,
    ScanResult,
    StorageType,
)
from aihound.mcp_server import (
    SCAN_CACHE_TTL,
    _cache,
    _check_mcp_dep,
    _filter_by_risk,
    _finding_id,
    _finding_to_mcp,
    _parse_risk,
    _results_to_mcp,
    _run_scan,
)
from aihound.remediation import hint_chmod


def _mk_finding(
    tool="Claude Code CLI",
    ctype="oauth_access_token",
    location="/home/u/.claude/.credentials.json",
    risk=RiskLevel.CRITICAL,
    raw_value="sk-ant-oat-supersecret-real-token-value",
):
    return CredentialFinding(
        tool_name=tool,
        credential_type=ctype,
        storage_type=StorageType.PLAINTEXT_JSON,
        location=location,
        exists=True,
        risk_level=risk,
        value_preview="sk-ant-...xxxx",
        raw_value=raw_value,
        remediation="Restrict file permissions: chmod 600 " + location,
        remediation_hint=hint_chmod("600", location),
    )


@pytest.fixture(autouse=True)
def _reset_cache():
    """Clear the module-level cache before each test."""
    _cache.clear()
    yield
    _cache.clear()


class TestFindingId:
    def test_stable_across_calls(self):
        f = _mk_finding()
        assert _finding_id(f) == _finding_id(f)

    def test_different_for_different_findings(self):
        assert _finding_id(_mk_finding(location="/a")) != _finding_id(_mk_finding(location="/b"))

    def test_is_opaque_hex_string(self):
        fid = _finding_id(_mk_finding())
        assert len(fid) == 16
        assert all(c in "0123456789abcdef" for c in fid)


class TestFindingToMcp:
    def test_excludes_raw_value_always(self):
        f = _mk_finding(raw_value="sk-ant-realsecret-should-never-leak")
        d = _finding_to_mcp(f)
        assert "raw_value" not in d
        # Double-check: the secret text itself must not appear anywhere
        assert "realsecret" not in str(d)

    def test_includes_value_preview(self):
        f = _mk_finding()
        d = _finding_to_mcp(f)
        assert d["value_preview"] == "sk-ant-...xxxx"

    def test_includes_finding_id(self):
        f = _mk_finding()
        d = _finding_to_mcp(f)
        assert d["finding_id"] == _finding_id(f)

    def test_includes_remediation_and_hint(self):
        f = _mk_finding()
        d = _finding_to_mcp(f)
        assert d["remediation"].startswith("Restrict file permissions")
        assert d["remediation_hint"] == {"action": "chmod", "args": ["600", f.location]}


class TestResultsToMcp:
    def test_empty_results(self):
        out = _results_to_mcp([], "9.9.9")
        assert out["findings"] == []
        assert out["errors"] == []
        assert out["summary"]["total_findings"] == 0
        assert out["scan_metadata"]["aihound_version"] == "9.9.9"

    def test_counts_findings_by_risk(self):
        r = ScanResult(
            scanner_name="t", platform="linux",
            findings=[
                _mk_finding(risk=RiskLevel.CRITICAL),
                _mk_finding(risk=RiskLevel.CRITICAL, location="/b"),
                _mk_finding(risk=RiskLevel.HIGH, location="/c"),
            ],
        )
        out = _results_to_mcp([r], "3.0.0")
        assert out["summary"]["total_findings"] == 3
        assert out["summary"]["by_risk"]["critical"] == 2
        assert out["summary"]["by_risk"]["high"] == 1
        assert out["summary"]["by_risk"]["info"] == 0

    def test_errors_are_scanner_prefixed(self):
        r = ScanResult(scanner_name="MyTool", platform="linux", errors=["boom"])
        out = _results_to_mcp([r], "3.0.0")
        assert out["errors"] == ["[MyTool] boom"]

    def test_no_raw_value_in_serialized_output(self):
        r = ScanResult(
            scanner_name="t", platform="linux",
            findings=[_mk_finding(raw_value="sk-ant-realsecret-abc123")],
        )
        out = _results_to_mcp([r], "3.0.0")
        assert "realsecret" not in str(out)


class TestParseRisk:
    def test_valid_levels(self):
        assert _parse_risk("critical") == RiskLevel.CRITICAL
        assert _parse_risk("HIGH") == RiskLevel.HIGH
        assert _parse_risk("info") == RiskLevel.INFO

    def test_invalid_returns_none(self):
        assert _parse_risk("bogus") is None

    def test_empty_returns_none(self):
        assert _parse_risk("") is None
        assert _parse_risk(None) is None


class TestFilterByRisk:
    def test_none_min_risk_returns_original(self):
        r = ScanResult(scanner_name="t", platform="linux",
                       findings=[_mk_finding(risk=RiskLevel.INFO)])
        out = _filter_by_risk([r], None)
        assert len(out[0].findings) == 1

    def test_drops_below_threshold(self):
        r = ScanResult(scanner_name="t", platform="linux", findings=[
            _mk_finding(risk=RiskLevel.INFO, location="/a"),
            _mk_finding(risk=RiskLevel.MEDIUM, location="/b"),
            _mk_finding(risk=RiskLevel.CRITICAL, location="/c"),
        ])
        out = _filter_by_risk([r], RiskLevel.HIGH)
        assert len(out[0].findings) == 1
        assert out[0].findings[0].risk_level == RiskLevel.CRITICAL


class TestRunScanCache:
    def test_cache_hit_within_ttl(self):
        # Mock get_all_scanners to return a controllable fake
        fake_result = ScanResult(scanner_name="fake", platform="linux",
                                 findings=[_mk_finding()])

        class FakeScanner:
            def __init__(self):
                self.call_count = 0
            def name(self): return "fake"
            def slug(self): return "fake"
            def is_applicable(self): return True
            def run(self, show_secrets=False):
                self.call_count += 1
                return fake_result

        fake = FakeScanner()
        with mock.patch("aihound.mcp_server.get_all_scanners", return_value=[fake]):
            _run_scan(tools=["fake"])
            _run_scan(tools=["fake"])  # cached
            assert fake.call_count == 1

    def test_force_bypasses_cache(self):
        class FakeScanner:
            def __init__(self):
                self.call_count = 0
            def name(self): return "fake"
            def slug(self): return "fake"
            def is_applicable(self): return True
            def run(self, show_secrets=False):
                self.call_count += 1
                return ScanResult(scanner_name="fake", platform="linux")

        fake = FakeScanner()
        with mock.patch("aihound.mcp_server.get_all_scanners", return_value=[fake]):
            _run_scan(tools=["fake"])
            _run_scan(tools=["fake"], force=True)
            assert fake.call_count == 2

    def test_cache_key_distinguishes_tool_sets(self):
        class FakeScanner:
            def __init__(self, slug):
                self._slug = slug
                self.call_count = 0
            def name(self): return self._slug
            def slug(self): return self._slug
            def is_applicable(self): return True
            def run(self, show_secrets=False):
                self.call_count += 1
                return ScanResult(scanner_name=self._slug, platform="linux")

        a = FakeScanner("a")
        b = FakeScanner("b")
        with mock.patch("aihound.mcp_server.get_all_scanners", return_value=[a, b]):
            _run_scan(tools=["a"])
            _run_scan(tools=["b"])  # different cache key, fresh scan
            assert a.call_count == 1
            assert b.call_count == 1

    def test_show_secrets_never_propagates(self):
        """The MCP cache path must never pass show_secrets=True."""
        captured = {}

        class FakeScanner:
            def name(self): return "fake"
            def slug(self): return "fake"
            def is_applicable(self): return True
            def run(self, show_secrets=False):
                captured["show_secrets"] = show_secrets
                return ScanResult(scanner_name="fake", platform="linux")

        with mock.patch("aihound.mcp_server.get_all_scanners", return_value=[FakeScanner()]):
            _run_scan(tools=["fake"], force=True)
        assert captured["show_secrets"] is False


class TestCheckMcpDep:
    def test_raises_without_mcp_installed(self):
        # We simulate the "mcp not installed" scenario by making the import fail
        with mock.patch.dict("sys.modules", {"mcp": None}):
            # Also need to force re-import by removing from cache
            import sys
            removed = {}
            for mod in list(sys.modules):
                if mod == "mcp" or mod.startswith("mcp."):
                    removed[mod] = sys.modules.pop(mod)
            sys.modules["mcp"] = None  # triggers ImportError on `import mcp`
            try:
                with pytest.raises(ImportError, match="aihound\\[mcp\\]"):
                    _check_mcp_dep()
            finally:
                sys.modules.pop("mcp", None)
                sys.modules.update(removed)
