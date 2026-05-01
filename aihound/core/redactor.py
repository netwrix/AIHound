"""Secret value masking and redaction."""

from __future__ import annotations

import re

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


# Pre-compiled patterns for redact_line
_PREFIX_PATTERN = "|".join(re.escape(p) for p in sorted(KNOWN_PREFIXES.keys(), key=len, reverse=True))
_REDACT_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_\-])((?:" + _PREFIX_PATTERN + r")[A-Za-z0-9_\-./+=]{16,})"
)
_REDACT_CONTEXT_RE = re.compile(
    r"""(?ix)
    (
      (?:api[_-]?key|token|secret|password|passwd|auth[a-z_-]*|bearer)\s*[=:]\s*
    | export\s+[A-Z_][A-Z0-9_]*\s*=\s*
    | -H\s+["']?Authorization:\s*Bearer\s+
    | -H\s+["']?x-api-key:\s*
    | --api-key\s+
    | --token\s+
    )
    ["']?([A-Za-z0-9_\-./+=]{20,})["']?
""",
)


def redact_line(line: str) -> str:
    """Redact any credential values found in a line of text.

    Uses KNOWN_PREFIXES to find and mask known token prefixes, and also
    redacts values after common assignment/header patterns like ``=``,
    ``export VAR=value``, ``-H Authorization: Bearer``, etc.

    Returns the line with credential values replaced by masked forms.
    """
    # Pass 1: Replace known-prefix tokens
    def _mask_prefix_match(m: re.Match) -> str:
        return mask_value(m.group(1))

    result = _REDACT_TOKEN_RE.sub(_mask_prefix_match, line)

    # Pass 2: Replace context-based credential values
    def _mask_context_match(m: re.Match) -> str:
        prefix_part = m.group(1)
        value_part = m.group(2)
        return prefix_part + mask_value(value_part)

    result = _REDACT_CONTEXT_RE.sub(_mask_context_match, result)

    return result


def identify_credential_type(value: str) -> str | None:
    """Try to identify what kind of credential a value is based on its prefix."""
    for prefix, name in sorted(KNOWN_PREFIXES.items(), key=lambda x: len(x[0]), reverse=True):
        if value.startswith(prefix):
            return name
    return None
