"""Tests for Persistent Environment scanner."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from aihound.core.scanner import RiskLevel, StorageType


class TestPersistentEnvLinuxParsing:
    def test_detects_ai_var_in_etc_environment(self):
        from aihound.scanners.persistent_env import PersistentEnvScanner
        scanner = PersistentEnvScanner()
        text = 'PATH="/usr/bin"\nOPENAI_API_KEY=sk-test1234567890abcdef\nLANG=en_US.UTF-8'
        findings = scanner._scan_kv_content(text, Path("/etc/environment"), False, is_system=True)
        assert len(findings) == 1
        assert findings[0].risk_level == RiskLevel.CRITICAL

    def test_ignores_non_ai_vars_in_etc_environment(self):
        from aihound.scanners.persistent_env import PersistentEnvScanner
        scanner = PersistentEnvScanner()
        text = 'PATH="/usr/bin"\nLANG=en_US.UTF-8'
        findings = scanner._scan_kv_content(text, Path("/etc/environment"), False, is_system=True)
        assert len(findings) == 0

    def test_detects_export_in_profile_d(self):
        from aihound.scanners.persistent_env import PersistentEnvScanner
        scanner = PersistentEnvScanner()
        text = '#!/bin/bash\nexport ANTHROPIC_API_KEY="sk-ant-api03-testvalue1234567890"'
        findings = scanner._scan_export_content(text, Path("/etc/profile.d/ai.sh"), False, is_system=True)
        assert len(findings) == 1
        assert findings[0].risk_level == RiskLevel.CRITICAL

    def test_detects_var_in_environment_d_conf(self):
        from aihound.scanners.persistent_env import PersistentEnvScanner
        scanner = PersistentEnvScanner()
        text = 'GEMINI_API_KEY=AIzaSyTestValue1234567890'
        findings = scanner._scan_kv_content(text, Path("/home/u/.config/environment.d/ai.conf"), False, is_system=False)
        assert len(findings) == 1
        assert findings[0].risk_level == RiskLevel.HIGH

    def test_detects_var_in_pam_environment(self):
        from aihound.scanners.persistent_env import PersistentEnvScanner
        scanner = PersistentEnvScanner()
        text = 'OPENAI_API_KEY DEFAULT=sk-test1234567890abcdef'
        findings = scanner._scan_pam_content(text, Path("/home/u/.pam_environment"), False)
        assert len(findings) == 1

    def test_skips_large_profile_d_file(self):
        from aihound.scanners.persistent_env import PersistentEnvScanner, _MAX_PROFILE_D_SIZE
        scanner = PersistentEnvScanner()
        assert _MAX_PROFILE_D_SIZE == 65536


class TestPersistentEnvMacOsPlist:
    def test_detects_env_var_in_plist_dict(self):
        from aihound.scanners.persistent_env import PersistentEnvScanner
        scanner = PersistentEnvScanner()
        env_dict = {"OPENAI_API_KEY": "sk-test1234567890abcdef", "PATH": "/usr/bin"}
        findings = scanner._scan_plist_env_dict(env_dict, Path("/Users/u/Library/LaunchAgents/my.plist"), False, is_system=False)
        assert len(findings) == 1
        assert "OPENAI_API_KEY" in findings[0].notes[0] or "OpenAI" in findings[0].credential_type

    def test_ignores_non_ai_plist_vars(self):
        from aihound.scanners.persistent_env import PersistentEnvScanner
        scanner = PersistentEnvScanner()
        env_dict = {"PATH": "/usr/bin", "HOME": "/Users/u"}
        findings = scanner._scan_plist_env_dict(env_dict, Path("/Users/u/Library/LaunchAgents/my.plist"), False, is_system=False)
        assert len(findings) == 0

    def test_system_plist_is_critical(self):
        from aihound.scanners.persistent_env import PersistentEnvScanner
        scanner = PersistentEnvScanner()
        env_dict = {"OPENAI_API_KEY": "sk-test1234567890abcdef"}
        findings = scanner._scan_plist_env_dict(env_dict, Path("/Library/LaunchDaemons/my.plist"), False, is_system=True)
        assert len(findings) == 1
        assert findings[0].risk_level == RiskLevel.CRITICAL


class TestPersistentEnvRegistryParsing:
    def test_parses_reg_query_output(self):
        from aihound.scanners.persistent_env import PersistentEnvScanner
        scanner = PersistentEnvScanner()
        reg_output = (
            "HKEY_CURRENT_USER\\Environment\n"
            "    OPENAI_API_KEY    REG_SZ    sk-test1234567890abcdef\n"
            "    Path    REG_EXPAND_SZ    C:\\Windows\\system32\n"
        )
        findings = scanner._parse_reg_output(reg_output, "HKCU\\Environment", False, is_system=False)
        assert len(findings) == 1
        assert findings[0].risk_level == RiskLevel.HIGH

    def test_system_registry_is_critical(self):
        from aihound.scanners.persistent_env import PersistentEnvScanner
        scanner = PersistentEnvScanner()
        reg_output = (
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment\n"
            "    OPENAI_API_KEY    REG_SZ    sk-test1234567890abcdef\n"
        )
        findings = scanner._parse_reg_output(reg_output, "HKLM\\...", False, is_system=True)
        assert len(findings) == 1
        assert findings[0].risk_level == RiskLevel.CRITICAL

    def test_ignores_non_ai_registry_vars(self):
        from aihound.scanners.persistent_env import PersistentEnvScanner
        scanner = PersistentEnvScanner()
        reg_output = (
            "HKEY_CURRENT_USER\\Environment\n"
            "    Path    REG_EXPAND_SZ    C:\\Windows\\system32\n"
            "    TEMP    REG_SZ    C:\\Users\\u\\Temp\n"
        )
        findings = scanner._parse_reg_output(reg_output, "HKCU\\Environment", False, is_system=False)
        assert len(findings) == 0
