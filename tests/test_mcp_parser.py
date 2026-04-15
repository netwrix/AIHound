"""Tests for the MCP config parser."""

import json
from pathlib import Path

from aihound.core.mcp import parse_mcp_config
from aihound.core.scanner import RiskLevel


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_parse_mcp_inline_secret():
    config = json.loads((FIXTURES_DIR / "claude_desktop_config.json").read_text())
    findings = parse_mcp_config(
        config,
        source_path=FIXTURES_DIR / "claude_desktop_config.json",
        tool_name="Test",
    )

    # Should find the inline ADO_MCP_AUTH_TOKEN
    inline_secrets = [f for f in findings if "mcp_env:ADO_MCP_AUTH_TOKEN" in f.credential_type]
    assert len(inline_secrets) == 1
    assert "Inline secret" in inline_secrets[0].notes[1]


def test_parse_mcp_env_reference():
    config = json.loads((FIXTURES_DIR / "claude_desktop_config.json").read_text())
    findings = parse_mcp_config(
        config,
        source_path=FIXTURES_DIR / "claude_desktop_config.json",
        tool_name="Test",
    )

    # The ${GITHUB_TOKEN} reference should be INFO level
    env_refs = [f for f in findings if "env_ref" in f.credential_type]
    assert len(env_refs) == 1
    assert env_refs[0].risk_level == RiskLevel.INFO


def test_parse_mcp_empty():
    findings = parse_mcp_config(
        {},
        source_path=FIXTURES_DIR / "claude_desktop_config.json",
        tool_name="Test",
    )
    assert findings == []
