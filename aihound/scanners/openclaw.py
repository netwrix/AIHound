"""Scanner for OpenClaw AI agent platform credentials."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from aihound.core.scanner import (
    BaseScanner, CredentialFinding, ScanResult, StorageType, RiskLevel,
)
from aihound.core.platform import (
    detect_platform, Platform, get_home, get_wsl_windows_home,
)
from aihound.core.redactor import mask_value
from aihound.core.permissions import get_file_permissions, get_file_owner, assess_risk, get_file_mtime, describe_staleness
from aihound.remediation import hint_manual
from aihound.scanners import register

logger = logging.getLogger("aihound.scanners.openclaw")

# Token/secret keys to look for in JSON config files
SECRET_KEYS = [
    "accessToken", "access_token", "refreshToken", "refresh_token",
    "apiKey", "api_key", "token", "auth_token", "secret",
    "password", "botToken", "bot_token", "clientSecret", "client_secret",
]


@register
class OpenClawScanner(BaseScanner):
    def name(self) -> str:
        return "OpenClaw"

    def slug(self) -> str:
        return "openclaw"

    def scan(self, show_secrets: bool = False) -> ScanResult:
        plat = detect_platform()
        result = ScanResult(scanner_name=self.name(), platform=plat.value)

        for base in self._get_base_paths(plat):
            self._scan_auth_profiles(base, result, show_secrets)
            self._scan_credentials_dir(base, result, show_secrets)
            self._scan_secrets_json(base, result, show_secrets)
            self._scan_main_config(base, result, show_secrets)
            self._scan_env_file(base, result, show_secrets)
            self._scan_legacy_oauth(base, result, show_secrets)

        return result

    def _get_base_paths(self, plat: Platform) -> list[Path]:
        paths = [get_home() / ".openclaw"]

        if plat == Platform.WSL:
            win_home = get_wsl_windows_home()
            if win_home:
                paths.append(win_home / ".openclaw")

        return paths

    # --- Auth Profiles (per-agent OAuth + API keys) ---

    def _scan_auth_profiles(
        self, base: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        agents_dir = base / "agents"
        if not agents_dir.exists():
            logger.debug("OpenClaw agents dir not found: %s", agents_dir)
            return

        for agent_dir in agents_dir.iterdir():
            if not agent_dir.is_dir():
                continue
            auth_file = agent_dir / "agent" / "auth-profiles.json"
            if not auth_file.exists():
                continue

            logger.debug("Reading auth profiles: %s", auth_file)
            perms = get_file_permissions(auth_file)
            owner = get_file_owner(auth_file)
            mtime = get_file_mtime(auth_file)

            try:
                data = json.loads(auth_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("Failed to parse %s: %s", auth_file, e, exc_info=True)
                result.errors.append(f"Failed to parse {auth_file}: {e}")
                continue

            agent_name = agent_dir.name
            self._extract_secrets_recursive(
                data, auth_file, perms, owner, mtime, result, show_secrets,
                context=f"agent:{agent_name}",
            )

    # --- Credentials directory (WhatsApp, Telegram, channel allowlists) ---

    def _scan_credentials_dir(
        self, base: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        creds_dir = base / "credentials"
        if not creds_dir.exists():
            logger.debug("OpenClaw credentials dir not found: %s", creds_dir)
            return

        logger.debug("Scanning OpenClaw credentials dir: %s", creds_dir)

        # WhatsApp credentials
        wa_dir = creds_dir / "whatsapp"
        if wa_dir.exists():
            for account_dir in wa_dir.iterdir():
                if not account_dir.is_dir():
                    continue
                creds_file = account_dir / "creds.json"
                if creds_file.exists():
                    self._scan_json_file(
                        creds_file, result, show_secrets,
                        context=f"whatsapp:{account_dir.name}",
                    )

        # Scan all JSON files in credentials root (oauth.json, allowlists, etc.)
        for json_file in creds_dir.glob("*.json"):
            self._scan_json_file(json_file, result, show_secrets, context="credentials")

    # --- secrets.json ---

    def _scan_secrets_json(
        self, base: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        path = base / "secrets.json"
        if not path.exists():
            return

        logger.debug("Reading secrets.json: %s", path)
        perms = get_file_permissions(path)
        owner = get_file_owner(path)
        mtime = get_file_mtime(path)

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to parse %s: %s", path, e, exc_info=True)
            result.errors.append(f"Failed to parse {path}: {e}")
            return

        if isinstance(data, dict):
            self._extract_secrets_recursive(
                data, path, perms, owner, mtime, result, show_secrets,
                context="secrets.json",
            )

    # --- Main config (openclaw.json) ---

    def _scan_main_config(
        self, base: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        path = base / "openclaw.json"
        if not path.exists():
            return

        logger.debug("Reading main config: %s", path)
        perms = get_file_permissions(path)
        owner = get_file_owner(path)
        mtime = get_file_mtime(path)

        # openclaw.json is JSON5 but stdlib json handles most cases
        try:
            content = path.read_text(encoding="utf-8")
            # Strip JS-style comments for basic JSON5 compat
            lines = []
            for line in content.splitlines():
                stripped = line.lstrip()
                if stripped.startswith("//"):
                    continue
                lines.append(line)
            data = json.loads("\n".join(lines))
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to parse %s: %s", path, e, exc_info=True)
            result.errors.append(f"Failed to parse {path}: {e}")
            return

        if isinstance(data, dict):
            # Check gateway auth token
            gateway = data.get("gateway", {})
            if isinstance(gateway, dict):
                auth = gateway.get("auth", {})
                if isinstance(auth, dict):
                    token = auth.get("token")
                    if token and isinstance(token, str) and len(token) > 8:
                        notes = ["OpenClaw gateway auth token (inline)"]
                        if mtime:
                            notes.append(f"File last modified: {describe_staleness(mtime)}")
                        result.findings.append(CredentialFinding(
                            tool_name=self.name(),
                            credential_type="gateway_auth_token",
                            storage_type=StorageType.PLAINTEXT_JSON,
                            location=str(path),
                            exists=True,
                            risk_level=assess_risk(StorageType.PLAINTEXT_JSON, path),
                            value_preview=mask_value(token, show_full=show_secrets),
                            raw_value=token if show_secrets else None,
                            file_permissions=perms,
                            file_owner=owner,
                            file_modified=mtime,
                            remediation="Use SecretRef (env:, file:) instead of inline secrets",
                            remediation_hint=hint_manual(
                                "Use SecretRef (env:, file:) instead of inline secrets",
                                suggested_format="env:VAR_NAME",
                            ),
                            notes=notes,
                        ))

            # Check channel configs for inline tokens
            channels = data.get("channels", {})
            if isinstance(channels, dict):
                self._extract_secrets_recursive(
                    channels, path, perms, owner, mtime, result, show_secrets,
                    context="channels",
                )

            # Check agent model configs for API keys
            agents = data.get("agents", {})
            if isinstance(agents, dict):
                self._extract_secrets_recursive(
                    agents, path, perms, owner, mtime, result, show_secrets,
                    context="agents",
                )

    # --- .env file ---

    def _scan_env_file(
        self, base: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        path = base / ".env"
        if not path.exists():
            return

        logger.debug("Reading .env: %s", path)
        perms = get_file_permissions(path)
        owner = get_file_owner(path)
        mtime = get_file_mtime(path)
        storage = StorageType.PLAINTEXT_ENV

        try:
            content = path.read_text(encoding="utf-8")
        except OSError:
            return

        secret_patterns = ["KEY", "TOKEN", "SECRET", "PASSWORD", "AUTH", "CREDENTIAL"]
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip("'\"")
                if value and any(p in key.upper() for p in secret_patterns):
                    notes = ["From OpenClaw .env file"]
                    if mtime:
                        notes.append(f"File last modified: {describe_staleness(mtime)}")
                    result.findings.append(CredentialFinding(
                        tool_name=self.name(),
                        credential_type=f"env_file:{key}",
                        storage_type=storage,
                        location=str(path),
                        exists=True,
                        risk_level=assess_risk(storage, path),
                        value_preview=mask_value(value, show_full=show_secrets),
                        raw_value=value if show_secrets else None,
                        file_permissions=perms,
                        file_owner=owner,
                        file_modified=mtime,
                        remediation="Use SecretRef (env:, file:) instead of inline secrets",
                        remediation_hint=hint_manual(
                            "Use SecretRef (env:, file:) instead of inline secrets",
                            suggested_format="env:VAR_NAME",
                        ),
                        notes=notes,
                    ))

    # --- Legacy oauth.json ---

    def _scan_legacy_oauth(
        self, base: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        path = base / "credentials" / "oauth.json"
        if not path.exists():
            return

        logger.debug("Reading legacy oauth.json: %s", path)
        perms = get_file_permissions(path)
        owner = get_file_owner(path)
        mtime = get_file_mtime(path)

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to parse %s: %s", path, e, exc_info=True)
            return

        if isinstance(data, dict):
            self._extract_secrets_recursive(
                data, path, perms, owner, mtime, result, show_secrets,
                context="legacy_oauth",
            )

    # --- Helpers ---

    def _scan_json_file(
        self, path: Path, result: ScanResult, show_secrets: bool, context: str = "",
    ) -> None:
        perms = get_file_permissions(path)
        owner = get_file_owner(path)
        mtime = get_file_mtime(path)

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return

        if isinstance(data, dict):
            self._extract_secrets_recursive(
                data, path, perms, owner, mtime, result, show_secrets,
                context=context,
            )

    def _extract_secrets_recursive(
        self, data: dict, path: Path, perms, owner, mtime,
        result: ScanResult, show_secrets: bool,
        context: str = "", depth: int = 0,
    ) -> None:
        if depth > 10:
            return

        for key, value in data.items():
            if isinstance(value, str) and len(value) > 8:
                if self._is_secret_key(key) or self._looks_like_token(value):
                    # Skip SecretRef values (they reference external sources, not inline secrets)
                    if value.startswith("env:") or value.startswith("file:") or value.startswith("exec:"):
                        notes = [
                            f"Context: {context}" if context else "",
                            "SecretRef (not inline — references external source)",
                        ]
                        if mtime:
                            notes.append(f"File last modified: {describe_staleness(mtime)}")
                        result.findings.append(CredentialFinding(
                            tool_name=self.name(),
                            credential_type=f"secret_ref:{key}",
                            storage_type=StorageType.PLAINTEXT_JSON,
                            location=str(path),
                            exists=True,
                            risk_level=RiskLevel.INFO,
                            value_preview=value,
                            file_modified=mtime,
                            notes=notes,
                        ))
                        continue

                    storage = StorageType.PLAINTEXT_JSON
                    notes = []
                    if context:
                        notes.append(f"Context: {context}")
                    notes.append("Plaintext credential in OpenClaw config")
                    if mtime:
                        notes.append(f"File last modified: {describe_staleness(mtime)}")

                    result.findings.append(CredentialFinding(
                        tool_name=self.name(),
                        credential_type=key,
                        storage_type=storage,
                        location=str(path),
                        exists=True,
                        risk_level=assess_risk(storage, path),
                        value_preview=mask_value(value, show_full=show_secrets),
                        raw_value=value if show_secrets else None,
                        file_permissions=perms,
                        file_owner=owner,
                        file_modified=mtime,
                        remediation="Use SecretRef (env:, file:) instead of inline secrets",
                        remediation_hint=hint_manual(
                            "Use SecretRef (env:, file:) instead of inline secrets",
                            suggested_format="env:VAR_NAME",
                        ),
                        notes=notes,
                    ))

            elif isinstance(value, dict):
                self._extract_secrets_recursive(
                    value, path, perms, owner, mtime, result, show_secrets,
                    context=context, depth=depth + 1,
                )
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        self._extract_secrets_recursive(
                            item, path, perms, owner, mtime, result, show_secrets,
                            context=context, depth=depth + 1,
                        )

    @staticmethod
    def _is_secret_key(key: str) -> bool:
        key_lower = key.lower()
        secret_keywords = [
            "token", "key", "secret", "password", "passwd", "auth",
            "credential", "cred", "apikey", "api_key", "accesstoken",
            "refreshtoken", "bottoken", "clientsecret",
        ]
        return any(kw in key_lower for kw in secret_keywords)

    @staticmethod
    def _looks_like_token(value: str) -> bool:
        if len(value) < 20:
            return False
        if value.startswith(("/", "http://", "https://", "env:", "file:", "exec:")):
            return False
        alphanumeric_ratio = sum(c.isalnum() or c in "-_." for c in value) / len(value)
        return alphanumeric_ratio > 0.8
