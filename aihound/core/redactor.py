"""Secret value masking and redaction."""

from __future__ import annotations

# Known credential prefixes and their display names
KNOWN_PREFIXES = {
    "sk-ant-": "Anthropic",
    "sk-ant-ort": "Anthropic Refresh",
    "sk-ant-oat": "Anthropic Access",
    "sk-": "OpenAI/Generic",
    "ghp_": "GitHub PAT (classic)",
    "gho_": "GitHub OAuth",
    "ghu_": "GitHub User-to-Server",
    "ghs_": "GitHub Server-to-Server",
    "github_pat_": "GitHub PAT (fine-grained)",
    "xoxb-": "Slack Bot",
    "xoxp-": "Slack User",
    "xoxa-": "Slack App",
    "AKIA": "AWS Access Key",
    "AIza": "Google API Key",
    "ya29.": "Google OAuth Access",
}


def mask_value(value: str, show_full: bool = False) -> str:
    """Mask a credential value, preserving known prefixes and last 4 chars.

    Examples:
        sk-ant-oat01-abc...xF2q
        ghp_abc1...9xYz
        ***REDACTED***  (for short values)
    """
    if show_full:
        return value

    if not value or len(value) <= 8:
        return "***REDACTED***"

    # Find the longest matching known prefix
    matched_prefix = ""
    for prefix in sorted(KNOWN_PREFIXES.keys(), key=len, reverse=True):
        if value.startswith(prefix):
            matched_prefix = prefix
            break

    if matched_prefix:
        # Show prefix + a few more chars + ... + last 4
        extra = min(4, len(value) - len(matched_prefix) - 4)
        if extra > 0:
            preview_start = value[: len(matched_prefix) + extra]
        else:
            preview_start = value[: len(matched_prefix)]
        return f"{preview_start}...{value[-4:]}"

    # No known prefix: show first 6 + ... + last 4
    return f"{value[:6]}...{value[-4:]}"


def identify_credential_type(value: str) -> str | None:
    """Try to identify what kind of credential a value is based on its prefix."""
    for prefix, name in sorted(KNOWN_PREFIXES.items(), key=lambda x: len(x[0]), reverse=True):
        if value.startswith(prefix):
            return name
    return None
