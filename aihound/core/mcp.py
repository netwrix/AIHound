"""Shared MCP (Model Context Protocol) configuration parser."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from aihound.core.scanner import CredentialFinding, StorageType, RiskLevel
from aihound.core.redactor import mask_value
from aihound.core.permissions import (
    get_file_permissions,
    get_file_owner,
    assess_risk,
    get_file_mtime,
    describe_staleness,
)
from aihound.remediation import hint_manual, hint_migrate_to_env

logger = logging.getLogger("aihound.core.mcp")


# Keywords that indicate an env var or value contains a secret
SECRET_KEY_PATTERNS = [
    "token", "key", "secret", "password", "passwd", "auth",
    "credential", "cred", "api_key", "apikey", "access_key",
    "bearer", "jwt",
]

# Env var names that are NEVER secrets — runtime/path/locale plumbing.
# Skip the secret heuristic entirely for these to suppress false positives like
# `PYTHONPATH=C:\Users\...\aicreds` getting flagged as a credential.
# Names are matched case-insensitively. Add new entries when a real-world
# false positive shows up.
KNOWN_NON_SECRET_KEYS = {
    # PATH-family
    "PATH", "PYTHONPATH", "NODE_PATH", "CLASSPATH",
    "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH",
    "GOPATH", "GOROOT", "GOBIN", "CARGO_HOME", "RUSTUP_HOME",
    # User / session identity
    "HOME", "USER", "USERNAME", "LOGNAME", "USERPROFILE",
    "HOMEDRIVE", "HOMEPATH",
    # Locale / timezone
    "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_MESSAGES",
    "LC_NUMERIC", "LC_TIME", "LC_COLLATE", "LC_MONETARY",
    "TZ",
    # Temp / runtime dirs
    "TMP", "TMPDIR", "TEMP", "XDG_RUNTIME_DIR", "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME", "XDG_DATA_HOME",
    # Shell + display
    "SHELL", "TERM", "TERM_PROGRAM", "PWD", "OLDPWD",
    "DISPLAY", "WAYLAND_DISPLAY", "COLORTERM",
    # Logging / debug flags (boolean-ish, harmless)
    "DEBUG", "VERBOSE", "LOG_LEVEL", "LOGLEVEL",
    "PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE",
    "NODE_ENV", "RUST_LOG", "RUST_BACKTRACE",
    # Node-specific
    "NODE_OPTIONS", "NPM_CONFIG_PREFIX",
    # CI / orchestration noise
    "CI", "GITHUB_ACTIONS", "RUNNER_OS",
    # Misc OS plumbing
    "OS", "OSTYPE", "MACHTYPE", "PROCESSOR_ARCHITECTURE",
    "SYSTEMROOT", "WINDIR", "COMSPEC",
}

# Env var references that are NOT inline secrets (they reference external vars)
ENV_VAR_REFERENCE_PATTERN = "${"


def _collect_mcp_blocks(data: dict) -> list[tuple[dict, str]]:
    """Gather all mcpServers maps: top-level and per-project.

    Returns a list of (servers_dict, project_path) tuples.
    project_path is empty string for the top-level block.
    """
    blocks: list[tuple[dict, str]] = []

    # Top-level mcpServers
    top = data.get("mcpServers", {})
    if isinstance(top, dict) and top:
        blocks.append((top, ""))

    # Per-project mcpServers (projects.<path>.mcpServers)
    projects = data.get("projects", {})
    if isinstance(projects, dict):
        for proj_path, proj_cfg in projects.items():
            if isinstance(proj_cfg, dict):
                proj_servers = proj_cfg.get("mcpServers", {})
                if isinstance(proj_servers, dict) and proj_servers:
                    blocks.append((proj_servers, proj_path))

    return blocks


def parse_mcp_config(
    data: dict,
    source_path: Path,
    tool_name: str,
    show_secrets: bool = False,
) -> list[CredentialFinding]:
    """Parse mcpServers from any tool's config and find embedded credentials.

    Works with Claude Desktop, Claude Code, Cursor, Cline, VS Code MCP configs.
    Scans both top-level mcpServers and per-project mcpServers blocks
    (projects.<path>.mcpServers).
    """
    findings = []
    blocks = _collect_mcp_blocks(data)
    if not blocks:
        return findings

    perms = get_file_permissions(source_path)
    owner = get_file_owner(source_path)

    for mcp_servers, project_path in blocks:
        for server_name, server_config in mcp_servers.items():
            if not isinstance(server_config, dict):
                continue

            def _build_notes(*extra: str) -> list[str]:
                notes = [f"MCP server: {server_name}"]
                if project_path:
                    notes.append(f"Project scope: {project_path}")
                notes.extend(extra)
                mtime = get_file_mtime(source_path)
                if mtime is not None:
                    notes.append(f"Config last modified {describe_staleness(mtime)}")
                return notes

            # Check env block for secrets
            env = server_config.get("env", {})
            if isinstance(env, dict):
                for key, value in env.items():
                    if not isinstance(value, str):
                        continue

                    # Allowlist: PATH-family / locale / shell vars are never secrets
                    if key.upper() in KNOWN_NON_SECRET_KEYS:
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
                            notes=_build_notes("References environment variable (not inline secret)"),
                            file_modified=get_file_mtime(source_path),
                            remediation="Verify env var is set in a secure environment, not committed to source",
                            remediation_hint=hint_manual(
                                "Verify env var is set in a secure environment, not committed to source"
                            ),
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
                            notes=_build_notes("Inline secret in config"),
                            file_modified=get_file_mtime(source_path),
                            remediation="Move secret to environment variable or secret manager",
                            remediation_hint=hint_migrate_to_env([], str(source_path)),
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
                                notes=_build_notes("References environment variable"),
                                file_modified=get_file_mtime(source_path),
                                remediation="Verify env var is set in a secure environment, not committed to source",
                                remediation_hint=hint_manual(
                                    "Verify env var is set in a secure environment, not committed to source"
                                ),
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
                                notes=_build_notes("Inline auth header"),
                                file_modified=get_file_mtime(source_path),
                                remediation="Move secret to environment variable or secret manager",
                                remediation_hint=hint_migrate_to_env([], str(source_path)),
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
                            notes=_build_notes(f"Token in CLI arg position {i}"),
                            file_modified=get_file_mtime(source_path),
                            remediation="Move secret to environment variable or secret manager",
                            remediation_hint=hint_migrate_to_env([], str(source_path)),
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
    # npm scoped package names (e.g. @perplexity-ai/mcp-server) — not secrets
    if value.startswith("@") and "/" in value:
        return False
    # Windows paths: drive letter + colon + separator (e.g. C:\foo, d:/bar)
    if len(value) >= 3 and value[0].isalpha() and value[1] == ":" and value[2] in ("\\", "/"):
        return False
    alphanumeric_ratio = sum(c.isalnum() or c in "-_." for c in value) / len(value)
    return alphanumeric_ratio > 0.8
