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


def test_windows_path_in_env_is_not_a_secret():
    """A Windows path value (e.g. PYTHONPATH=C:\\Users\\...) must not be
    flagged as an inline secret. Heuristic previously missed these because
    they don't start with '/' or 'http' and are mostly alphanumeric."""
    config = {
        "mcpServers": {
            "myserver": {
                "command": "python",
                "args": ["-m", "mymodule"],
                "env": {
                    "PYTHONPATH": "C:\\Users\\DarrylBaker\\Documents\\SecurityResearch\\aicreds",
                },
            }
        }
    }
    findings = parse_mcp_config(
        config,
        source_path=FIXTURES_DIR / "claude_desktop_config.json",
        tool_name="Test",
    )
    inline_secrets = [f for f in findings if f.credential_type.startswith("mcp_env:")]
    assert inline_secrets == [], (
        f"Windows path should not be flagged as inline secret, got: "
        f"{[(f.credential_type, f.value_preview) for f in inline_secrets]}"
    )


def test_known_non_secret_keys_are_skipped():
    """KNOWN_NON_SECRET_KEYS allowlist suppresses runtime/path/locale env vars
    even when their values would otherwise look credential-like to the heuristic.

    Defense-in-depth on top of the Windows-path fix: catches future false
    positives that hit the value heuristic but are obviously plumbing.
    """
    # Mix of common runtime vars with values that LOOK secret-y to the heuristic
    # (long, alphanumeric, no clear path prefix).
    config = {
        "mcpServers": {
            "myserver": {
                "env": {
                    # Long colon-separated PATH on Linux — would pass the
                    # alphanumeric ratio but is obviously not a secret.
                    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin",
                    "NODE_OPTIONS": "--max-old-space-size=4096-abcdef-randomlooking",
                    "LANG": "en_US.UTF-8.somethingelseAAAAAAAAAA",
                    "TZ": "America/Los_Angeles_aaaaaaaaaaaaaaa",
                    "TERM": "xterm-256color-aaaaaaaaaaaaaaaaaa",
                    # And a real secret that should still fire — proves we're
                    # not just turning the whole scanner off.
                    "MY_API_TOKEN": "sk-ant-oat01-realsecret-aaaaaaaaaaaaaaaaaaaaaaaaaa",
                },
            }
        }
    }
    findings = parse_mcp_config(
        config,
        source_path=FIXTURES_DIR / "claude_desktop_config.json",
        tool_name="Test",
    )
    fired_for = sorted(
        f.credential_type.removeprefix("mcp_env:")
        for f in findings
        if f.credential_type.startswith("mcp_env:")
    )
    # The real secret must still fire; the allowlisted vars must NOT.
    assert "MY_API_TOKEN" in fired_for, (
        "Real secret in env block should still be detected even with "
        "KNOWN_NON_SECRET_KEYS in place"
    )
    leaked = [k for k in fired_for if k in {"PATH", "NODE_OPTIONS", "LANG", "TZ", "TERM"}]
    assert leaked == [], f"Allowlisted env vars must not be flagged: {leaked}"


def test_known_non_secret_keys_case_insensitive():
    """Lowercase / mixed-case versions of allowlisted keys must also be skipped."""
    config = {
        "mcpServers": {
            "s": {
                "env": {
                    "pythonpath": "C:\\Users\\foo\\some-long-path-aaaaaaaaaaa",
                    "Path": "C:\\Windows\\System32;C:\\Tools",
                }
            }
        }
    }
    findings = parse_mcp_config(
        config,
        source_path=FIXTURES_DIR / "claude_desktop_config.json",
        tool_name="Test",
    )
    leaked = [
        f.credential_type for f in findings if f.credential_type.startswith("mcp_env:")
    ]
    assert leaked == [], f"Case-mismatched allowlisted keys should be skipped: {leaked}"
