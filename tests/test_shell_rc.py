"""Tests for Shell RC scanner."""

from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from aihound.core.scanner import RiskLevel, StorageType


class TestShellRcPaths:
    def test_linux_includes_bashrc(self):
        from aihound.scanners.shell_rc import ShellRcScanner
        scanner = ShellRcScanner()
        with patch("aihound.scanners.shell_rc.detect_platform") as mock_plat, \
             patch("aihound.scanners.shell_rc.get_home", return_value=Path("/home/testuser")):
            from aihound.core.platform import Platform
            mock_plat.return_value = Platform.LINUX
            paths = scanner._get_rc_paths(Platform.LINUX)
            path_strs = [str(p) for p in paths]
            assert "/home/testuser/.bashrc" in path_strs
            assert "/home/testuser/.zshrc" in path_strs
            assert "/home/testuser/.config/fish/config.fish" in path_strs

    def test_linux_includes_env_files(self):
        from aihound.scanners.shell_rc import ShellRcScanner
        scanner = ShellRcScanner()
        with patch("aihound.scanners.shell_rc.get_home", return_value=Path("/home/testuser")):
            from aihound.core.platform import Platform
            paths = scanner._get_env_paths(Platform.LINUX)
            path_strs = [str(p) for p in paths]
            assert "/home/testuser/.env" in path_strs
            assert "/home/testuser/.config/.env" in path_strs
            assert "/home/testuser/.docker/.env" in path_strs

    def test_windows_includes_ps_profiles(self):
        from aihound.scanners.shell_rc import ShellRcScanner
        scanner = ShellRcScanner()
        with patch("aihound.scanners.shell_rc.get_home", return_value=Path("C:/Users/testuser")):
            from aihound.core.platform import Platform
            paths = scanner._get_rc_paths(Platform.WINDOWS)
            path_strs = [str(p) for p in paths]
            assert any("PowerShell" in p and "profile.ps1" in p for p in path_strs)
            assert any("WindowsPowerShell" in p and "profile.ps1" in p for p in path_strs)

    def test_wsl_includes_both_linux_and_windows(self):
        from aihound.scanners.shell_rc import ShellRcScanner
        scanner = ShellRcScanner()
        with patch("aihound.scanners.shell_rc.get_home", return_value=Path("/home/testuser")), \
             patch("aihound.scanners.shell_rc.get_wsl_windows_home", return_value=Path("/mnt/c/Users/testuser")):
            from aihound.core.platform import Platform
            paths = scanner._get_rc_paths(Platform.WSL)
            path_strs = [str(p) for p in paths]
            assert "/home/testuser/.bashrc" in path_strs
            assert any("mnt/c" in p and "profile.ps1" in p for p in path_strs)


class TestShellRcDetection:
    def test_detects_export_with_known_ai_var(self):
        from aihound.scanners.shell_rc import ShellRcScanner
        scanner = ShellRcScanner()
        lines = 'export OPENAI_API_KEY="sk-test1234567890abcdef"'
        findings = scanner._scan_content(lines, Path("/home/u/.bashrc"), False)
        assert len(findings) >= 1
        assert any("OPENAI_API_KEY" in f.credential_type or "OpenAI" in f.credential_type for f in findings)

    def test_detects_fish_set_with_known_ai_var(self):
        from aihound.scanners.shell_rc import ShellRcScanner
        scanner = ShellRcScanner()
        lines = 'set -gx ANTHROPIC_API_KEY "sk-ant-api03-testvalue1234567890"'
        findings = scanner._scan_content(lines, Path("/home/u/.config/fish/config.fish"), False)
        assert len(findings) >= 1

    def test_detects_powershell_env_set(self):
        from aihound.scanners.shell_rc import ShellRcScanner
        scanner = ShellRcScanner()
        lines = '$env:OPENAI_API_KEY = "sk-test1234567890abcdef"'
        findings = scanner._scan_content(lines, Path("C:/Users/u/Documents/PowerShell/Microsoft.PowerShell_profile.ps1"), False)
        assert len(findings) >= 1

    def test_detects_env_file_var_equals_value(self):
        from aihound.scanners.shell_rc import ShellRcScanner
        scanner = ShellRcScanner()
        lines = 'OPENAI_API_KEY=sk-test1234567890abcdef'
        findings = scanner._scan_content(lines, Path("/home/u/.env"), False)
        assert len(findings) >= 1

    def test_ignores_non_ai_export(self):
        from aihound.scanners.shell_rc import ShellRcScanner
        scanner = ShellRcScanner()
        lines = 'export EDITOR=vim\nexport PATH=/usr/bin:$PATH'
        findings = scanner._scan_content(lines, Path("/home/u/.bashrc"), False)
        assert len(findings) == 0

    def test_detects_raw_known_prefix_token(self):
        from aihound.scanners.shell_rc import ShellRcScanner
        scanner = ShellRcScanner()
        lines = '# my key: sk-ant-api03-testvalue1234567890abcdef'
        findings = scanner._scan_content(lines, Path("/home/u/.bashrc"), False)
        assert len(findings) >= 1

    def test_env_file_uses_plaintext_env_storage_type(self):
        from aihound.scanners.shell_rc import ShellRcScanner
        scanner = ShellRcScanner()
        lines = 'OPENAI_API_KEY=sk-test1234567890abcdef'
        findings = scanner._scan_content(lines, Path("/home/u/.env"), False)
        assert len(findings) >= 1
        assert findings[0].storage_type == StorageType.PLAINTEXT_ENV

    def test_rc_file_uses_plaintext_file_storage_type(self):
        from aihound.scanners.shell_rc import ShellRcScanner
        scanner = ShellRcScanner()
        lines = 'export OPENAI_API_KEY="sk-test1234567890abcdef"'
        findings = scanner._scan_content(lines, Path("/home/u/.bashrc"), False)
        assert len(findings) >= 1
        assert findings[0].storage_type == StorageType.PLAINTEXT_FILE
