"""Shared MCP (Model Context Protocol) configuration parser."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from aihound.core.scanner import CredentialFinding, StorageType, RiskLevel
from aihound.core.redactor import mask_value
from aihound.core.permissions import get_file_permissions, get_file_owner, assess_risk

logger = logging.getLogger("aihound.core.mcp")


# Keywords that indicate an env var or value contains a secret
SECRET_KEY_PATTERNS = [
    "token", "key", "secret", "password", "passwd", "auth",
    "credential", "cred", "api_key", "apikey", "access_key",
    "bearer", "jwt",
]

# Env var references that are NOT inline secrets (they reference external vars)
ENV_VAR_REFERENCE_PATTERN = "${"


def parse_mcp_config(
    data: dict,
    source_path: Path,
    tool_name: str,
    show_secrets: bool = False,
) -> list[CredentialFinding]:
    """Parse mcpServers from any tool's config and find embedded credentials.

    Works with Claude Desktop, Claude Code, Cursor, Cline, VS Code MCP configs.
    """
    findings = []
    mcp_servers = data.get("mcpServers", {})
    if not isinstance(mcp_servers, dict):
        return findings

    perms = get_file_permissions(source_path)
    owner = get_file_owner(source_path)

    for server_name, server_config in mcp_servers.items():
        if not isinstance(server_config, dict):
            continue

        # Check env block for secrets
        env = server_config.get("env", {})
        if isinstance(env, dict):
            for key, value in env.items():
                if not isinstance(value, str):
                    continue

                if _is_env_var_reference(value):
                    # This references an external env var, not an inline secret
                    findings.append(CredentialFinding(
                        tool_name=tool_name,
                        credential_type=f"mcp_env_ref:{key}",
                        storage_type=StorageType.PLAINTEXT_JSON,
                        location=str(source_path),
                        exists=True,
                        risk_level=RiskLevel.INFO,
                        value_preview=value,
                        notes=[
                            f"MCP server: {server_name}",
                            "References environment variable (not inline secret)",
                        ],
                    ))
                elif _looks_like_secret_key(key) or _looks_like_secret_value(value):
                    findings.append(CredentialFinding(
                        tool_name=tool_name,
                        credential_type=f"mcp_env:{key}",
                        storage_type=StorageType.PLAINTEXT_JSON,
                        location=str(source_path),
                        exists=True,
                        risk_level=assess_risk(StorageType.PLAINTEXT_JSON, source_path),
                        value_preview=mask_value(value, show_full=show_secrets),
                        raw_value=value if show_secrets else None,
                        file_permissions=perms,
                        file_owner=owner,
                        notes=[f"MCP server: {server_name}", "Inline secret in config"],
                    ))

        # Check headers block (for HTTP transport MCP servers)
        headers = server_config.get("headers", {})
        if isinstance(headers, dict):
            for key, value in headers.items():
                if not isinstance(value, str):
                    continue
                key_lower = key.lower()
                if key_lower in ("authorization", "x-api-key", "api-key"):
                    if _is_env_var_reference(value):
                        findings.append(CredentialFinding(
                            tool_name=tool_name,
                            credential_type=f"mcp_header:{key}",
                            storage_type=StorageType.PLAINTEXT_JSON,
                            location=str(source_path),
                            exists=True,
                            risk_level=RiskLevel.INFO,
                            value_preview=value,
                            notes=[
                                f"MCP server: {server_name}",
                                "References environment variable",
                            ],
                        ))
                    else:
                        findings.append(CredentialFinding(
                            tool_name=tool_name,
                            credential_type=f"mcp_header:{key}",
                            storage_type=StorageType.PLAINTEXT_JSON,
                            location=str(source_path),
                            exists=True,
                            risk_level=assess_risk(StorageType.PLAINTEXT_JSON, source_path),
                            value_preview=mask_value(value, show_full=show_secrets),
                            raw_value=value if show_secrets else None,
                            file_permissions=perms,
                            file_owner=owner,
                            notes=[f"MCP server: {server_name}", "Inline auth header"],
                        ))

        # Check args for tokens (some MCP servers pass tokens as CLI args)
        args = server_config.get("args", [])
        if isinstance(args, list):
            for i, arg in enumerate(args):
                if not isinstance(arg, str):
                    continue
                if _looks_like_secret_value(arg) and not arg.startswith("-"):
                    findings.append(CredentialFinding(
                        tool_name=tool_name,
                        credential_type=f"mcp_arg[{i}]",
                        storage_type=StorageType.PLAINTEXT_JSON,
                        location=str(source_path),
                        exists=True,
                        risk_level=assess_risk(StorageType.PLAINTEXT_JSON, source_path),
                        value_preview=mask_value(arg, show_full=show_secrets),
                        raw_value=arg if show_secrets else None,
                        file_permissions=perms,
                        file_owner=owner,
                        notes=[f"MCP server: {server_name}", f"Token in CLI arg position {i}"],
                    ))

    return findings


def parse_mcp_file(
    path: Path,
    tool_name: str,
    show_secrets: bool = False,
) -> tuple[list[CredentialFinding], list[str]]:
    """Parse an MCP config file and return findings and errors."""
    findings = []
    errors = []

    if not path.exists():
        logger.debug("MCP config not found: %s", path)
        return findings, errors

    logger.debug("Parsing MCP config: %s", path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to parse MCP config %s: %s", path, e, exc_info=True)
        errors.append(f"Failed to parse MCP config {path}: {e}")
        return findings, errors

    if isinstance(data, dict):
        findings = parse_mcp_config(data, path, tool_name, show_secrets)

    return findings, errors


def _is_env_var_reference(value: str) -> bool:
    """Check if value is an env var reference like ${VAR_NAME}."""
    return ENV_VAR_REFERENCE_PATTERN in value


def _looks_like_secret_key(key: str) -> bool:
    """Check if env var name suggests it contains a secret."""
    key_lower = key.lower()
    return any(pattern in key_lower for pattern in SECRET_KEY_PATTERNS)


def _looks_like_secret_value(value: str) -> bool:
    """Heuristic: does this value look like a credential?"""
    if len(value) < 20:
        return False
    if value.startswith("/") or value.startswith("http"):
        return False
    alphanumeric_ratio = sum(c.isalnum() or c in "-_." for c in value) / len(value)
    return alphanumeric_ratio > 0.8
