"""Scanner for Ollama configuration and security posture."""

from __future__ import annotations

import json
import logging
import os
import subprocess
from pathlib import Path

from aihound.core.scanner import (
    BaseScanner, CredentialFinding, ScanResult, StorageType, RiskLevel,
)
from aihound.core.platform import detect_platform, Platform, get_home, get_wsl_windows_home
from aihound.core.redactor import mask_value
from aihound.core.permissions import get_file_permissions, get_file_owner, assess_risk
from aihound.scanners import register

logger = logging.getLogger("aihound.scanners.ollama")

# Ollama-related environment variables
OLLAMA_ENV_VARS = {
    "OLLAMA_HOST": "Ollama server bind address (default: 127.0.0.1:11434)",
    "OLLAMA_ORIGINS": "Ollama CORS allowed origins",
    "OLLAMA_MODELS": "Ollama model storage directory",
    "OLLAMA_DEBUG": "Ollama debug mode flag",
    "OLLAMA_API_KEY": "Ollama API key (if using proxy/auth layer)",
    "OLLAMA_NUM_PARALLEL": "Ollama concurrent request limit",
}


@register
class OllamaScanner(BaseScanner):
    def name(self) -> str:
        return "Ollama"

    def slug(self) -> str:
        return "ollama"

    def scan(self, show_secrets: bool = False) -> ScanResult:
        plat = detect_platform()
        result = ScanResult(scanner_name=self.name(), platform=plat.value)

        # Check environment variables
        self._scan_env_vars(result, show_secrets)

        # Check for dangerous network binding
        self._check_network_exposure(result)

        # Check systemd service file for embedded config (Linux)
        if plat in (Platform.LINUX, Platform.WSL):
            self._scan_systemd_service(result, show_secrets)

        # Check Ollama config directories for any auth/config files
        for path in self._get_config_paths(plat):
            self._scan_config_dir(path, result, show_secrets)

        return result

    def _get_config_paths(self, plat: Platform) -> list[Path]:
        paths = []
        home = get_home()

        paths.append(home / ".ollama")

        if plat in (Platform.LINUX, Platform.WSL):
            # Systemd service user path
            paths.append(Path("/usr/share/ollama/.ollama"))

        if plat == Platform.WSL:
            win_home = get_wsl_windows_home()
            if win_home:
                paths.append(win_home / ".ollama")

        return paths

    def _scan_env_vars(self, result: ScanResult, show_secrets: bool) -> None:
        for var_name, description in OLLAMA_ENV_VARS.items():
            value = os.environ.get(var_name)
            if not value:
                continue

            # Check for dangerous OLLAMA_HOST binding
            if var_name == "OLLAMA_HOST" and ("0.0.0.0" in value):
                result.findings.append(CredentialFinding(
                    tool_name=self.name(),
                    credential_type="network_binding",
                    storage_type=StorageType.ENVIRONMENT_VAR,
                    location=f"${var_name}",
                    exists=True,
                    risk_level=RiskLevel.HIGH,
                    value_preview=value,
                    notes=[
                        "Ollama API bound to all interfaces (0.0.0.0)",
                        "No built-in authentication — any network device can access the API",
                    ],
                ))
                continue

            # Check for wildcard CORS
            if var_name == "OLLAMA_ORIGINS" and value == "*":
                result.findings.append(CredentialFinding(
                    tool_name=self.name(),
                    credential_type="cors_config",
                    storage_type=StorageType.ENVIRONMENT_VAR,
                    location=f"${var_name}",
                    exists=True,
                    risk_level=RiskLevel.MEDIUM,
                    value_preview=value,
                    notes=["Wildcard CORS — any website can make requests to Ollama API"],
                ))
                continue

            # Check for API key (if using auth proxy)
            if var_name == "OLLAMA_API_KEY":
                result.findings.append(CredentialFinding(
                    tool_name=self.name(),
                    credential_type="api_key",
                    storage_type=StorageType.ENVIRONMENT_VAR,
                    location=f"${var_name}",
                    exists=True,
                    risk_level=RiskLevel.MEDIUM,
                    value_preview=mask_value(value, show_full=show_secrets),
                    raw_value=value if show_secrets else None,
                    notes=["Ollama API key (likely for auth proxy)"],
                ))
                continue

            # Non-secret config flags
            result.findings.append(CredentialFinding(
                tool_name=self.name(),
                credential_type=description,
                storage_type=StorageType.ENVIRONMENT_VAR,
                location=f"${var_name}",
                exists=True,
                risk_level=RiskLevel.INFO,
                value_preview=value,
                notes=["Configuration flag"],
            ))

    def _check_network_exposure(self, result: ScanResult) -> None:
        """Check if Ollama is currently running and listening on a non-localhost address."""
        try:
            proc = subprocess.run(
                ["ss", "-tlnp"],
                capture_output=True, text=True, timeout=5,
            )
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    if ":11434" in line and "0.0.0.0" in line:
                        result.findings.append(CredentialFinding(
                            tool_name=self.name(),
                            credential_type="network_exposure",
                            storage_type=StorageType.UNKNOWN,
                            location="listening on 0.0.0.0:11434",
                            exists=True,
                            risk_level=RiskLevel.CRITICAL,
                            notes=[
                                "Ollama API is currently listening on all interfaces",
                                "No built-in authentication — any device on the network can run inference",
                                "Recommendation: bind to 127.0.0.1 or use a reverse proxy with auth",
                            ],
                        ))
                        break
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            logger.debug("Could not check Ollama network binding (ss not available)")

    def _scan_systemd_service(self, result: ScanResult, show_secrets: bool) -> None:
        """Check systemd service file for embedded environment variables."""
        service_paths = [
            Path("/etc/systemd/system/ollama.service"),
            Path("/usr/lib/systemd/system/ollama.service"),
        ]

        for path in service_paths:
            if not path.exists():
                continue

            logger.debug("Reading systemd service: %s", path)
            perms = get_file_permissions(path)
            owner = get_file_owner(path)

            try:
                content = path.read_text(encoding="utf-8")
            except OSError as e:
                logger.warning("Failed to read %s: %s", path, e, exc_info=True)
                continue

            for line in content.splitlines():
                stripped = line.strip()
                if stripped.startswith("Environment=") or stripped.startswith("Environment ="):
                    _, _, env_val = stripped.partition("=")
                    env_val = env_val.strip().strip('"')

                    # Check for OLLAMA_HOST=0.0.0.0
                    if "OLLAMA_HOST" in env_val and "0.0.0.0" in env_val:
                        result.findings.append(CredentialFinding(
                            tool_name=self.name(),
                            credential_type="systemd_network_binding",
                            storage_type=StorageType.PLAINTEXT_INI,
                            location=str(path),
                            exists=True,
                            risk_level=RiskLevel.HIGH,
                            value_preview=env_val,
                            file_permissions=perms,
                            file_owner=owner,
                            notes=[
                                "Ollama systemd service configured to bind to 0.0.0.0",
                                "API exposed to network without authentication",
                            ],
                        ))

                    # Check for any secret-looking values
                    if any(kw in env_val.upper() for kw in ["KEY", "TOKEN", "SECRET", "PASSWORD"]):
                        result.findings.append(CredentialFinding(
                            tool_name=self.name(),
                            credential_type="systemd_env_secret",
                            storage_type=StorageType.PLAINTEXT_INI,
                            location=str(path),
                            exists=True,
                            risk_level=assess_risk(StorageType.PLAINTEXT_INI, path),
                            value_preview=mask_value(env_val, show_full=show_secrets),
                            raw_value=env_val if show_secrets else None,
                            file_permissions=perms,
                            file_owner=owner,
                            notes=["Secret in Ollama systemd service file"],
                        ))

    def _scan_config_dir(
        self, base_path: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        if not base_path.exists():
            logger.debug("Ollama config dir not found: %s", base_path)
            return

        logger.debug("Scanning Ollama config dir: %s", base_path)

        # Check for any JSON config files that might contain auth info
        for json_file in base_path.glob("*.json"):
            perms = get_file_permissions(json_file)
            owner = get_file_owner(json_file)

            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue

            if isinstance(data, dict):
                for key in ("api_key", "apiKey", "token", "auth_token", "password"):
                    value = data.get(key)
                    if value and isinstance(value, str) and len(value) > 8:
                        result.findings.append(CredentialFinding(
                            tool_name=self.name(),
                            credential_type=key,
                            storage_type=StorageType.PLAINTEXT_JSON,
                            location=str(json_file),
                            exists=True,
                            risk_level=assess_risk(StorageType.PLAINTEXT_JSON, json_file),
                            value_preview=mask_value(value, show_full=show_secrets),
                            raw_value=value if show_secrets else None,
                            file_permissions=perms,
                            file_owner=owner,
                        ))
