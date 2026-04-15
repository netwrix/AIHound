"""Scanner for Google Gemini CLI and Google Cloud credentials."""

from __future__ import annotations

import json
from pathlib import Path

from aihound.core.scanner import (
    BaseScanner, CredentialFinding, ScanResult, StorageType,
)
from aihound.core.platform import (
    detect_platform, Platform, get_home, get_wsl_windows_home, get_xdg_config,
)
from aihound.core.redactor import mask_value
from aihound.core.permissions import get_file_permissions, get_file_owner, assess_risk
from aihound.scanners import register


@register
class GeminiScanner(BaseScanner):
    def name(self) -> str:
        return "Gemini CLI / GCloud"

    def slug(self) -> str:
        return "gemini"

    def scan(self, show_secrets: bool = False) -> ScanResult:
        plat = detect_platform()
        result = ScanResult(scanner_name=self.name(), platform=plat.value)

        # Check .env files
        for path in self._get_env_file_paths(plat):
            self._scan_env_file(path, result, show_secrets)

        # Check Application Default Credentials
        for path in self._get_adc_paths(plat):
            self._scan_adc(path, result, show_secrets)

        return result

    def _get_env_file_paths(self, plat: Platform) -> list[Path]:
        paths = []
        home = get_home()

        paths.append(home / ".gemini" / ".env")
        paths.append(home / ".env")

        if plat == Platform.WSL:
            win_home = get_wsl_windows_home()
            if win_home:
                paths.append(win_home / ".gemini" / ".env")
                paths.append(win_home / ".env")

        return paths

    def _get_adc_paths(self, plat: Platform) -> list[Path]:
        paths = []

        if plat in (Platform.LINUX, Platform.WSL):
            paths.append(
                get_xdg_config() / "gcloud" / "application_default_credentials.json"
            )
        elif plat == Platform.MACOS:
            paths.append(
                get_home() / "Library" / "Application Support" / "gcloud"
                / "application_default_credentials.json"
            )
            # Also check XDG location on macOS
            paths.append(
                get_home() / ".config" / "gcloud" / "application_default_credentials.json"
            )
        elif plat == Platform.WINDOWS:
            from aihound.core.platform import get_appdata
            appdata = get_appdata()
            if appdata:
                paths.append(appdata / "gcloud" / "application_default_credentials.json")

        if plat == Platform.WSL:
            from aihound.core.platform import get_appdata
            appdata = get_appdata()
            if appdata:
                paths.append(appdata / "gcloud" / "application_default_credentials.json")

        return paths

    def _scan_env_file(
        self, path: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        if not path.exists():
            return

        perms = get_file_permissions(path)
        owner = get_file_owner(path)
        storage = StorageType.PLAINTEXT_ENV

        try:
            content = path.read_text(encoding="utf-8")
        except OSError:
            return

        gemini_keys = [
            "GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS",
            "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
        ]

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip("'\"")

                if key in gemini_keys and value:
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
                        notes=[f"From .env file"],
                    ))

    def _scan_adc(
        self, path: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        if not path.exists():
            return

        perms = get_file_permissions(path)
        owner = get_file_owner(path)
        storage = StorageType.PLAINTEXT_JSON

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return

        if not isinstance(data, dict):
            return

        # ADC files contain client_secret, refresh_token, etc.
        token_fields = [
            ("client_secret", "gcloud_client_secret"),
            ("refresh_token", "gcloud_refresh_token"),
            ("private_key", "service_account_key"),
        ]

        for field_name, cred_type in token_fields:
            value = data.get(field_name)
            if value and isinstance(value, str):
                notes = []
                cred_kind = data.get("type", "unknown")
                notes.append(f"Credential type: {cred_kind}")

                result.findings.append(CredentialFinding(
                    tool_name=self.name(),
                    credential_type=cred_type,
                    storage_type=storage,
                    location=str(path),
                    exists=True,
                    risk_level=assess_risk(storage, path),
                    value_preview=mask_value(value, show_full=show_secrets),
                    raw_value=value if show_secrets else None,
                    file_permissions=perms,
                    file_owner=owner,
                    notes=notes,
                ))
