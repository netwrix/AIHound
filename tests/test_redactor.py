"""Tests for the redactor module."""

from aihound.core.redactor import mask_value, identify_credential_type


def test_mask_short_value():
    assert mask_value("abc") == "***REDACTED***"
    assert mask_value("12345678") == "***REDACTED***"


def test_mask_anthropic_key():
    key = "sk-ant-oat01-abc123def456ghi789jkl012mno345pqr"
    masked = mask_value(key)
    assert masked.startswith("sk-ant-oat01-")
    assert masked.endswith(f"...{key[-4:]}")
    assert "abc123def456ghi789" not in masked


def test_mask_github_pat():
    key = "ghp_abcdef1234567890abcdef1234567890"
    masked = mask_value(key)
    assert masked.startswith("ghp_")
    assert masked.endswith(f"...{key[-4:]}")


def test_mask_show_full():
    key = "sk-ant-oat01-fullvalue"
    assert mask_value(key, show_full=True) == key


def test_mask_unknown_prefix():
    key = "some_random_long_credential_value_here"
    masked = mask_value(key)
    assert masked.startswith("some_r")
    assert masked.endswith(f"...{key[-4:]}")


def test_identify_anthropic():
    assert identify_credential_type("sk-ant-oat01-xxx") == "Anthropic Access"
    assert identify_credential_type("sk-ant-ort01-xxx") == "Anthropic Refresh"


def test_identify_github():
    assert identify_credential_type("ghp_abcdef") == "GitHub PAT (classic)"
    assert identify_credential_type("gho_abcdef") == "GitHub OAuth"


def test_identify_aws():
    assert identify_credential_type("AKIAIOSFODNN7EXAMPLE") == "AWS Access Key"


def test_identify_unknown():
    assert identify_credential_type("random_string") is None
