"""Scanner for LM Studio configuration and credentials."""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

from aihound.core.scanner import (
    BaseScanner, CredentialFinding, ScanResult, StorageType, RiskLevel,
)
from aihound.core.platform import (
    detect_platform, Platform, get_home, get_appdata, get_wsl_windows_home,
    get_xdg_config,
)
from aihound.core.redactor import mask_value
from aihound.core.permissions import get_file_permissions, get_file_owner, assess_risk, get_file_mtime, describe_staleness
from aihound.remediation import hint_chmod, hint_manual, hint_network_bind
from aihound.scanners import register

logger = logging.getLogger("aihound.scanners.lm_studio")

# Token/secret keys to look for in config files
SECRET_KEYS = [
    "api_key", "apiKey", "token", "auth_token", "access_token",
    "hf_token", "huggingface_token", "huggingFaceToken",
    "password", "secret",
]


@register
class LMStudioScanner(BaseScanner):
    def name(self) -> str:
        return "LM Studio"

    def slug(self) -> str:
        return "lm-studio"

    def scan(self, show_secrets: bool = False) -> ScanResult:
        plat = detect_platform()
        result = ScanResult(scanner_name=self.name(), platform=plat.value)

        # Scan config directories for settings and credentials
        for path in self._get_config_paths(plat):
            self._scan_config_dir(path, result, show_secrets)

        # Check if LM Studio local server is exposed on non-localhost
        self._check_network_exposure(result)

        return result

    def _get_config_paths(self, plat: Platform) -> list[Path]:
        paths = []
        home = get_home()

        if plat == Platform.MACOS:
            paths.append(home / "Library" / "Application Support" / "LM Studio")

        elif plat == Platform.WINDOWS:
            appdata = get_appdata()
            if appdata:
                paths.append(appdata / "LM Studio")
            # Some versions use .cache
            localappdata = home / "AppData" / "Local"
            paths.append(localappdata / "LM Studio")

        elif plat in (Platform.LINUX, Platform.WSL):
            paths.append(get_xdg_config() / "LM Studio")
            # Flatpak path
            paths.append(home / ".var" / "app" / "com.lmstudio.lmstudio" / "config" / "LM Studio")

        if plat == Platform.WSL:
            appdata = get_appdata()
            if appdata:
                paths.append(appdata / "LM Studio")
            win_home = get_wsl_windows_home()
            if win_home:
                paths.append(win_home / "AppData" / "Local" / "LM Studio")

        return paths

    def _scan_config_dir(
        self, base_path: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        if not base_path.exists():
            logger.debug("LM Studio config dir not found: %s", base_path)
            return

        logger.debug("Scanning LM Studio config dir: %s", base_path)

        # Scan all JSON files in the config directory
        json_files = list(base_path.glob("*.json"))
        # Also check common subdirectories
        for subdir in ["config", "settings", "auth"]:
            sub = base_path / subdir
            if sub.exists():
                json_files.extend(sub.glob("*.json"))

        for json_file in json_files:
            self._scan_json_file(json_file, result, show_secrets)

        # Check for .env files
        for env_file in base_path.glob("*.env"):
            self._scan_env_file(env_file, result, show_secrets)
        env_file = base_path / ".env"
        if env_file.exists():
            self._scan_env_file(env_file, result, show_secrets)

    def _scan_json_file(
        self, path: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        perms = get_file_permissions(path)
        owner = get_file_owner(path)
        mtime = get_file_mtime(path)

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.debug("Could not parse %s: %s", path, e)
            return

        if isinstance(data, dict):
            self._extract_secrets(data, path, perms, owner, mtime, result, show_secrets)

    def _extract_secrets(
        self, data: dict, path: Path, perms, owner, mtime,
        result: ScanResult, show_secrets: bool,
    ) -> None:
        for key in SECRET_KEYS:
            value = data.get(key)
            if value and isinstance(value, str) and len(value) > 8:
                storage = StorageType.PLAINTEXT_JSON
                notes = []
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
                    remediation=_remediation,
                    remediation_hint=_remediation_hint,
                    notes=notes,
                ))

        # Check for Hugging Face token in nested structures
        # LM Studio may store HF auth for model downloads
        for nested_key in ("huggingFace", "huggingface", "hf", "auth", "credentials"):
            nested = data.get(nested_key)
            if isinstance(nested, dict):
                self._extract_secrets(nested, path, perms, owner, mtime, result, show_secrets)

        # Check for server config exposing non-localhost binding
        server = data.get("server") or data.get("localServer")
        if isinstance(server, dict):
            host = server.get("host", "")
            port = server.get("port", "")
            if isinstance(host, str) and "0.0.0.0" in host:
                notes = [
                    "LM Studio server configured to bind to all interfaces",
                    "No built-in authentication — network devices can access the API",
                ]
                if mtime:
                    notes.append(f"File last modified: {describe_staleness(mtime)}")
                result.findings.append(CredentialFinding(
                    tool_name=self.name(),
                    credential_type="server_network_binding",
                    storage_type=StorageType.PLAINTEXT_JSON,
                    location=str(path),
                    exists=True,
                    risk_level=RiskLevel.HIGH,
                    value_preview=f"{host}:{port}",
                    file_permissions=perms,
                    file_owner=owner,
                    file_modified=mtime,
                    remediation="Bind to 127.0.0.1 instead of 0.0.0.0",
                    remediation_hint=hint_network_bind("lm-studio", str(path), port if isinstance(port, int) else None),
                    notes=notes,
                ))

    def _scan_env_file(
        self, path: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        if not path.exists():
            return

        perms = get_file_permissions(path)
        owner = get_file_owner(path)
        mtime = get_file_mtime(path)
        storage = StorageType.PLAINTEXT_ENV

        try:
            content = path.read_text(encoding="utf-8")
        except OSError:
            return

        secret_patterns = ["KEY", "TOKEN", "SECRET", "PASSWORD", "AUTH"]
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip("'\"")
                if value and any(p in key.upper() for p in secret_patterns):
                    notes = ["From .env file in LM Studio config"]
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
                        remediation=_remediation,
                        remediation_hint=_remediation_hint,
                        notes=notes,
                    ))

    def _check_network_exposure(self, result: ScanResult) -> None:
        """Check if LM Studio server is listening on a non-localhost address."""
        try:
            proc = subprocess.run(
                ["ss", "-tlnp"],
                capture_output=True, text=True, timeout=5,
            )
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    if ":1234" in line and "0.0.0.0" in line:
                        result.findings.append(CredentialFinding(
                            tool_name=self.name(),
                            credential_type="network_exposure",
                            storage_type=StorageType.UNKNOWN,
                            location="listening on 0.0.0.0:1234",
                            exists=True,
                            risk_level=RiskLevel.CRITICAL,
                            remediation="Bind to 127.0.0.1 instead of 0.0.0.0",
                            remediation_hint=hint_network_bind("lm-studio", None, 1234),
                            notes=[
                                "LM Studio API server listening on all interfaces",
                                "No built-in authentication — network devices can access the API",
                                "Recommendation: bind to 127.0.0.1 or use a reverse proxy with auth",
                            ],
                        ))
                        break
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            logger.debug("Could not check LM Studio network binding (ss not available)")
