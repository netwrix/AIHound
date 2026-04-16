"""Tests for remediation hint builders."""

from __future__ import annotations

import json

import pytest

from aihound.remediation import (
    hint_change_config_value,
    hint_chmod,
    hint_manual,
    hint_migrate_to_env,
    hint_network_bind,
    hint_rotate_credential,
    hint_run_command,
    hint_use_credential_helper,
)


class TestHintShapes:
    def test_chmod(self):
        h = hint_chmod("600", "/home/u/file")
        assert h == {"action": "chmod", "args": ["600", "/home/u/file"]}

    def test_chmod_coerces_path_to_str(self):
        from pathlib import Path
        h = hint_chmod("600", Path("/tmp/x"))
        assert h["args"][1] == "/tmp/x"

    def test_migrate_to_env(self):
        h = hint_migrate_to_env(["OPENAI_API_KEY", "ANTHROPIC_API_KEY"], "/conf.yml")
        assert h["action"] == "migrate_to_env"
        assert h["env_vars"] == ["OPENAI_API_KEY", "ANTHROPIC_API_KEY"]
        assert h["source"] == "/conf.yml"

    def test_migrate_to_env_copies_list(self):
        # helper shouldn't hold a reference to caller's list
        names = ["A"]
        h = hint_migrate_to_env(names, "/x")
        names.append("B")
        assert h["env_vars"] == ["A"]

    def test_change_config_value(self):
        h = hint_change_config_value("server.host", "127.0.0.1", "/c.json")
        assert h == {
            "action": "change_config_value",
            "target": "server.host",
            "new_value": "127.0.0.1",
            "source": "/c.json",
        }

    def test_run_command_default_shell(self):
        h = hint_run_command(["echo hi"])
        assert h["shell"] == "bash"
        assert h["commands"] == ["echo hi"]

    def test_run_command_powershell(self):
        h = hint_run_command(["Remove-Item x"], shell="powershell")
        assert h["shell"] == "powershell"

    def test_use_credential_helper(self):
        h = hint_use_credential_helper("docker", ["credsStore"])
        assert h["action"] == "use_credential_helper"
        assert h["tool"] == "docker"
        assert h["helper_options"] == ["credsStore"]

    def test_rotate_credential(self):
        h = hint_rotate_credential("anthropic", "Go to console")
        assert h["action"] == "rotate_credential"
        assert h["provider"] == "anthropic"
        assert h["description"] == "Go to console"

    def test_manual_basic(self):
        h = hint_manual("Fix it yourself")
        assert h == {"action": "manual", "description": "Fix it yourself"}

    def test_manual_with_extra_fields(self):
        h = hint_manual("Fix it", suggested_tools=["vault"], severity="medium")
        assert h["suggested_tools"] == ["vault"]
        assert h["severity"] == "medium"

    def test_network_bind(self):
        h = hint_network_bind("ollama", "/etc/ollama.service", 11434)
        assert h["action"] == "change_config_value"
        assert h["service"] == "ollama"
        assert h["new_value"] == "127.0.0.1"
        assert h["source"] == "/etc/ollama.service"
        assert h["port"] == 11434

    def test_network_bind_without_source_or_port(self):
        h = hint_network_bind("ollama")
        assert "source" not in h
        assert "port" not in h


class TestHintsAreJSONSerializable:
    """Every hint must round-trip through JSON — MCP sends them over the wire."""

    @pytest.mark.parametrize("hint", [
        hint_chmod("600", "/x"),
        hint_migrate_to_env(["K"], "/x"),
        hint_change_config_value("t", "v", "/x"),
        hint_run_command(["cmd"], shell="bash"),
        hint_use_credential_helper("t", ["o"]),
        hint_rotate_credential("p", "d"),
        hint_manual("d", extra="field"),
        hint_network_bind("s", "/x", 80),
    ])
    def test_roundtrip(self, hint):
        encoded = json.dumps(hint)
        decoded = json.loads(encoded)
        assert decoded == hint


class TestActionTypeCoverage:
    """Guard against a new action slug slipping in without test coverage."""

    KNOWN_ACTIONS = {
        "chmod", "migrate_to_env", "change_config_value", "run_command",
        "use_credential_helper", "rotate_credential", "manual",
    }

    def test_all_helpers_produce_known_actions(self):
        for hint in [
            hint_chmod("600", "/x"),
            hint_migrate_to_env(["K"], "/x"),
            hint_change_config_value("t", "v", "/x"),
            hint_run_command(["cmd"]),
            hint_use_credential_helper("t", ["o"]),
            hint_rotate_credential("p", "d"),
            hint_manual("d"),
            hint_network_bind("s"),  # uses change_config_value under the hood
        ]:
            assert hint["action"] in self.KNOWN_ACTIONS
