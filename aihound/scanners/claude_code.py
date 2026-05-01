"""Scanner for Claude Code CLI credentials."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("aihound.scanners.claude_code")

from aihound.core.scanner import (
    BaseScanner,
    CredentialFinding,
    ScanResult,
    StorageType,
    RiskLevel,
)
from aihound.core.platform import detect_platform, Platform, get_home, get_wsl_windows_home
from aihound.core.redactor import mask_value
from aihound.core.permissions import get_file_permissions, get_file_owner, assess_risk, get_file_mtime, describe_staleness
from aihound.remediation import hint_chmod, hint_manual
from aihound.scanners import register


@register
class ClaudeCodeScanner(BaseScanner):
    def name(self) -> str:
        return "Claude Code CLI"

    def slug(self) -> str:
        return "claude-code"

    def scan(self, show_secrets: bool = False) -> ScanResult:
        plat = detect_platform()
        result = ScanResult(scanner_name=self.name(), platform=plat.value)

        # Collect all paths to check
        cred_paths = self._get_credential_paths(plat)
        config_paths = self._get_config_paths(plat)

        # Scan credential files
        for path in cred_paths:
            self._scan_credentials_file(path, result, show_secrets)

        # Scan config files for MCP server secrets
        # Primary files first, then backups; dedup across all
        seen_mcp_values: set[str] = set()
        primary_paths = [p for p in config_paths if ".backup" not in p.name]
        backup_paths = [p for p in config_paths if ".backup" in p.name]
        for path in primary_paths:
            self._scan_config_file(path, result, show_secrets, seen_mcp_values)

        # Count backup files that also contain MCP secrets
        backup_count = sum(1 for p in backup_paths if p.exists())
        for path in backup_paths:
            self._scan_config_file(path, result, show_secrets, seen_mcp_values)

        # Add backup exposure note to primary MCP findings
        if backup_count > 0:
            for f in result.findings:
                if f.credential_type.startswith("mcp_env:") and ".backup" not in f.location:
                    f.notes.append(
                        f"Also present in {backup_count} backup file(s) "
                        f"under ~/.claude/backups/"
                    )

        return result

    def _get_credential_paths(self, plat: Platform) -> list[Path]:
        paths = []
        home = get_home()

        # Linux/macOS: ~/.claude/.credentials.json
        creds = home / ".claude" / ".credentials.json"
        paths.append(creds)

        # WSL: also check Windows user's .claude
        if plat == Platform.WSL:
            win_home = get_wsl_windows_home()
            if win_home:
                paths.append(win_home / ".claude" / ".credentials.json")

        return paths

    def _get_config_paths(self, plat: Platform) -> list[Path]:
        paths = []
        home = get_home()

        # ~/.claude.json (global MCP config)
        paths.append(home / ".claude.json")
        # ~/.claude/settings.json
        paths.append(home / ".claude" / "settings.json")

        # Backup copies of .claude.json (contain same secrets)
        backup_dir = home / ".claude" / "backups"
        if backup_dir.is_dir():
            for backup in backup_dir.iterdir():
                if backup.name.startswith(".claude.json.backup"):
                    paths.append(backup)

        # WSL: also check Windows paths
        if plat == Platform.WSL:
            win_home = get_wsl_windows_home()
            if win_home:
                paths.append(win_home / ".claude.json")
                paths.append(win_home / ".claude" / "settings.json")
                win_backup_dir = win_home / ".claude" / "backups"
                if win_backup_dir.is_dir():
                    for backup in win_backup_dir.iterdir():
                        if backup.name.startswith(".claude.json.backup"):
                            paths.append(backup)

        return paths

    def _scan_credentials_file(
        self, path: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        if not path.exists():
            logger.debug("Credential file not found: %s", path)
            return

        logger.debug("Reading credential file: %s", path)
        perms = get_file_permissions(path)
        owner = get_file_owner(path)

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to parse %s: %s", path, e, exc_info=True)
            result.errors.append(f"Failed to parse {path}: {e}")
            return

        # The credentials file can be a dict with multiple auth entries
        if isinstance(data, dict):
            self._extract_auth_entries(data, path, perms, owner, result, show_secrets)
        elif isinstance(data, list):
            for entry in data:
                if isinstance(entry, dict):
                    self._extract_auth_entries(entry, path, perms, owner, result, show_secrets)

    def _extract_auth_entries(
        self,
        data: dict,
        path: Path,
        perms: Optional[str],
        owner: Optional[str],
        result: ScanResult,
        show_secrets: bool,
    ) -> None:
        storage = StorageType.PLAINTEXT_JSON
        risk = assess_risk(storage, path)
        mtime = get_file_mtime(path)

        # Check for various credential fields
        token_fields = [
            ("access", "oauth_access_token"),
            ("accessToken", "oauth_access_token"),
            ("refresh", "oauth_refresh_token"),
            ("refreshToken", "oauth_refresh_token"),
            ("apiKey", "api_key"),
            ("token", "auth_token"),
        ]

        for field_name, cred_type in token_fields:
            value = data.get(field_name)
            if value and isinstance(value, str):
                notes = []

                # Check for auth type
                auth_type = data.get("type")
                if auth_type:
                    notes.append(f"Auth type: {auth_type}")

                if mtime:
                    notes.append(f"File last modified: {describe_staleness(mtime)}")

                # Check for expiry
                expiry = None
                expires_val = data.get("expires") or data.get("expiresAt")
                if expires_val:
                    try:
                        if isinstance(expires_val, (int, float)):
                            # Could be seconds or milliseconds
                            if expires_val > 1e12:
                                expiry = datetime.fromtimestamp(expires_val / 1000, tz=timezone.utc)
                            else:
                                expiry = datetime.fromtimestamp(expires_val, tz=timezone.utc)
                            notes.append(f"Expires: {expiry.strftime('%Y-%m-%d %H:%M UTC')}")
                    except (ValueError, OSError):
                        pass

                if perms == "0600":
                    _remediation = "Credentials stored as plaintext; consider migrating to an OS credential store"
                    _remediation_hint = hint_manual("Consider migrating to an OS credential store")
                else:
                    _remediation = f"Restrict file permissions: chmod 600 {path}"
                    _remediation_hint = hint_chmod("600", str(path))

                result.findings.append(CredentialFinding(
                    tool_name=self.name(),
                    credential_type=cred_type,
                    storage_type=storage,
                    location=str(path),
                    exists=True,
                    risk_level=risk,
                    value_preview=mask_value(value, show_full=show_secrets),
                    raw_value=value if show_secrets else None,
                    file_permissions=perms,
                    file_owner=owner,
                    file_modified=mtime,
                    expiry=expiry,
                    remediation=_remediation,
                    remediation_hint=_remediation_hint,
                    notes=notes,
                ))

        # Recurse into nested dicts (e.g., per-provider credentials)
        for key, val in data.items():
            if key in [f[0] for f in token_fields]:
                continue
            if isinstance(val, dict):
                self._extract_auth_entries(val, path, perms, owner, result, show_secrets)

    def _scan_config_file(
        self, path: Path, result: ScanResult, show_secrets: bool,
        seen_mcp_values: Optional[set[str]] = None,
    ) -> None:
        if not path.exists():
            logger.debug("Config file not found: %s", path)
            return

        logger.debug("Reading config file: %s", path)
        perms = get_file_permissions(path)
        owner = get_file_owner(path)
        mtime = get_file_mtime(path)

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to parse %s: %s", path, e, exc_info=True)
            result.errors.append(f"Failed to parse {path}: {e}")
            return

        # Collect all MCP server blocks: top-level and per-project
        mcp_blocks: list[tuple[dict, Optional[str]]] = []  # (servers_dict, project_path)

        # Top-level mcpServers
        top_mcp = data.get("mcpServers", {})
        if isinstance(top_mcp, dict) and top_mcp:
            mcp_blocks.append((top_mcp, None))

        # Per-project mcpServers (projects.<path>.mcpServers)
        projects = data.get("projects", {})
        if isinstance(projects, dict):
            for project_path, project_cfg in projects.items():
                if isinstance(project_cfg, dict):
                    proj_mcp = project_cfg.get("mcpServers", {})
                    if isinstance(proj_mcp, dict) and proj_mcp:
                        mcp_blocks.append((proj_mcp, project_path))

        for mcp_servers, project_path in mcp_blocks:
            for server_name, server_config in mcp_servers.items():
                if not isinstance(server_config, dict):
                    continue

                env = server_config.get("env", {})
                if not isinstance(env, dict):
                    continue

                for env_key, env_value in env.items():
                    if not isinstance(env_value, str):
                        continue

                    # Deduplicate: skip if same value was already reported
                    # (from primary file or another backup)
                    dedup_key = f"{server_name}:{env_key}:{env_value}"
                    if dedup_key in seen_mcp_values:
                        continue
                    seen_mcp_values.add(dedup_key)

                    # Check if this looks like it contains a secret
                    if self._looks_like_secret(env_key, env_value):
                        notes = [f"MCP server: {server_name}"]
                        if project_path:
                            notes.append(f"Project scope: {project_path}")
                        if mtime:
                            notes.append(f"File last modified: {describe_staleness(mtime)}")

                        if perms == "0600":
                            _remediation = "Credentials stored as plaintext; consider migrating to an OS credential store"
                            _remediation_hint = hint_manual("Consider migrating to an OS credential store")
                        else:
                            _remediation = f"Restrict file permissions: chmod 600 {path}"
                            _remediation_hint = hint_chmod("600", str(path))

                        result.findings.append(CredentialFinding(
                            tool_name=self.name(),
                            credential_type=f"mcp_env:{env_key}",
                            storage_type=StorageType.PLAINTEXT_JSON,
                            location=str(path),
                            exists=True,
                            risk_level=assess_risk(StorageType.PLAINTEXT_JSON, path),
                            value_preview=mask_value(env_value, show_full=show_secrets),
                            raw_value=env_value if show_secrets else None,
                            file_permissions=perms,
                            file_owner=owner,
                            file_modified=mtime,
                            remediation=_remediation,
                            remediation_hint=_remediation_hint,
                            notes=notes,
                        ))

    @staticmethod
    def _looks_like_secret(key: str, value: str) -> bool:
        """Heuristic: does this env var key/value pair look like it contains a secret?"""
        key_lower = key.lower()
        secret_keywords = [
            "token", "key", "secret", "password", "passwd", "auth",
            "credential", "cred", "api_key", "apikey", "access_key",
        ]
        if any(kw in key_lower for kw in secret_keywords):
            return True

        # Check if value looks like a token (long alphanumeric string)
        if len(value) > 20 and not value.startswith("/") and not value.startswith("http"):
            # Probably not a path or URL
            alphanumeric_ratio = sum(c.isalnum() or c in "-_" for c in value) / len(value)
            if alphanumeric_ratio > 0.8:
                return True

        return False
