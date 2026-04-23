"""Tests for Shell History scanner."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from aihound.core.scanner import RiskLevel, StorageType


class TestShellHistoryPaths:
    def test_linux_includes_bash_history(self):
        from aihound.scanners.shell_history import ShellHistoryScanner
        scanner = ShellHistoryScanner()
        with patch("aihound.scanners.shell_history.get_home", return_value=Path("/home/testuser")):
            from aihound.core.platform import Platform
            paths = scanner._get_history_paths(Platform.LINUX)
            path_strs = [str(p) for p in paths]
            assert "/home/testuser/.bash_history" in path_strs
            assert "/home/testuser/.zsh_history" in path_strs
            assert "/home/testuser/.zhistory" in path_strs
            assert "/home/testuser/.local/share/fish/fish_history" in path_strs

    def test_zdotdir_override(self):
        from aihound.scanners.shell_history import ShellHistoryScanner
        scanner = ShellHistoryScanner()
        with patch("aihound.scanners.shell_history.get_home", return_value=Path("/home/testuser")), \
             patch.dict("os.environ", {"ZDOTDIR": "/home/testuser/.config/zsh"}):
            from aihound.core.platform import Platform
            paths = scanner._get_history_paths(Platform.LINUX)
            path_strs = [str(p) for p in paths]
            assert "/home/testuser/.config/zsh/.zsh_history" in path_strs

    def test_macos_same_as_linux(self):
        from aihound.scanners.shell_history import ShellHistoryScanner
        scanner = ShellHistoryScanner()
        with patch("aihound.scanners.shell_history.get_home", return_value=Path("/Users/testuser")):
            from aihound.core.platform import Platform
            linux_paths = scanner._get_history_paths(Platform.LINUX)
            macos_paths = scanner._get_history_paths(Platform.MACOS)
            assert len(linux_paths) > 0
            assert len(macos_paths) > 0


class TestShellHistoryDetection:
    def test_detects_known_prefix_token(self):
        from aihound.scanners.shell_history import ShellHistoryScanner
        scanner = ShellHistoryScanner()
        text = 'curl -H "Authorization: Bearer sk-ant-api03-testvalue1234567890abcdef" https://api.anthropic.com/v1/messages'
        findings = scanner._scan_history_content(text, Path("/home/u/.bash_history"), False)
        assert len(findings) >= 1

    def test_detects_export_in_history(self):
        from aihound.scanners.shell_history import ShellHistoryScanner
        scanner = ShellHistoryScanner()
        text = 'export OPENAI_API_KEY=sk-test1234567890abcdefghij'
        findings = scanner._scan_history_content(text, Path("/home/u/.bash_history"), False)
        assert len(findings) >= 1

    def test_detects_curl_api_key_header(self):
        from aihound.scanners.shell_history import ShellHistoryScanner
        scanner = ShellHistoryScanner()
        text = 'curl -H "x-api-key: sk-ant-api03-testvalue1234567890abcdef" https://example.com'
        findings = scanner._scan_history_content(text, Path("/home/u/.bash_history"), False)
        assert len(findings) >= 1

    def test_ignores_paths_and_urls(self):
        from aihound.scanners.shell_history import ShellHistoryScanner
        scanner = ShellHistoryScanner()
        text = 'cd /usr/local/bin/something-very-long-path-name\ncurl https://example.com/very-long-url-path-segment'
        findings = scanner._scan_history_content(text, Path("/home/u/.bash_history"), False)
        assert len(findings) == 0

    def test_deduplicates_same_value(self):
        from aihound.scanners.shell_history import ShellHistoryScanner
        scanner = ShellHistoryScanner()
        token = "sk-ant-api03-testvalue1234567890abcdef"
        text = f"curl -H 'x-api-key: {token}' url1\ncurl -H 'x-api-key: {token}' url2"
        findings = scanner._scan_history_content(text, Path("/home/u/.bash_history"), False)
        assert len(findings) == 1

    def test_bash_remediation_hint(self):
        from aihound.scanners.shell_history import ShellHistoryScanner
        scanner = ShellHistoryScanner()
        text = "sk-ant-api03-testvalue1234567890abcdef"
        findings = scanner._scan_history_content(text, Path("/home/u/.bash_history"), False)
        assert len(findings) >= 1
        assert findings[0].remediation_hint["shell"] == "bash"

    def test_zsh_remediation_hint(self):
        from aihound.scanners.shell_history import ShellHistoryScanner
        scanner = ShellHistoryScanner()
        text = "sk-ant-api03-testvalue1234567890abcdef"
        findings = scanner._scan_history_content(text, Path("/home/u/.zsh_history"), False)
        assert len(findings) >= 1
        assert findings[0].remediation_hint["shell"] == "zsh"

    def test_fish_remediation_hint(self):
        from aihound.scanners.shell_history import ShellHistoryScanner
        scanner = ShellHistoryScanner()
        text = "sk-ant-api03-testvalue1234567890abcdef"
        findings = scanner._scan_history_content(text, Path("/home/u/.local/share/fish/fish_history"), False)
        assert len(findings) >= 1
        assert findings[0].remediation_hint["shell"] == "fish"
