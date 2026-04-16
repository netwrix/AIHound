"""Scanner for Amazon Q Developer / AWS credentials."""

from __future__ import annotations

import configparser
import json
from pathlib import Path

from aihound.core.scanner import (
    BaseScanner, CredentialFinding, ScanResult, StorageType,
)
from aihound.core.platform import detect_platform, Platform, get_home, get_wsl_windows_home
from aihound.core.redactor import mask_value
from aihound.core.permissions import get_file_permissions, get_file_owner, assess_risk, get_file_mtime, describe_staleness
from aihound.remediation import hint_manual, hint_rotate_credential
from aihound.scanners import register


@register
class AmazonQScanner(BaseScanner):
    def name(self) -> str:
        return "Amazon Q / AWS"

    def slug(self) -> str:
        return "amazon-q"

    def scan(self, show_secrets: bool = False) -> ScanResult:
        plat = detect_platform()
        result = ScanResult(scanner_name=self.name(), platform=plat.value)

        for path in self._get_credential_paths(plat):
            self._scan_aws_credentials(path, result, show_secrets)

        for path in self._get_sso_cache_paths(plat):
            self._scan_sso_cache(path, result, show_secrets)

        return result

    def _get_credential_paths(self, plat: Platform) -> list[Path]:
        paths = []
        home = get_home()

        paths.append(home / ".aws" / "credentials")

        if plat == Platform.WSL:
            win_home = get_wsl_windows_home()
            if win_home:
                paths.append(win_home / ".aws" / "credentials")

        return paths

    def _get_sso_cache_paths(self, plat: Platform) -> list[Path]:
        paths = []
        home = get_home()

        paths.append(home / ".aws" / "sso" / "cache")

        if plat == Platform.WSL:
            win_home = get_wsl_windows_home()
            if win_home:
                paths.append(win_home / ".aws" / "sso" / "cache")

        return paths

    def _scan_aws_credentials(
        self, path: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        if not path.exists():
            return

        perms = get_file_permissions(path)
        owner = get_file_owner(path)
        mtime = get_file_mtime(path)
        storage = StorageType.PLAINTEXT_INI

        config = configparser.ConfigParser()
        try:
            config.read(str(path))
        except (configparser.Error, OSError) as e:
            result.errors.append(f"Failed to parse {path}: {e}")
            return

        for section in config.sections():
            for key in ("aws_access_key_id", "aws_secret_access_key", "aws_session_token"):
                value = config.get(section, key, fallback=None)
                if value:
                    notes = [f"AWS profile: [{section}]"]
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
                        remediation="Use AWS SSO or IAM roles instead of long-lived access keys",
                        remediation_hint=hint_manual(
                            "Use AWS SSO or IAM roles instead of long-lived access keys",
                            suggested_commands=["aws configure sso"],
                        ),
                        notes=notes,
                    ))

    def _scan_sso_cache(
        self, cache_dir: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        if not cache_dir.exists():
            return

        for json_file in cache_dir.glob("*.json"):
            perms = get_file_permissions(json_file)
            owner = get_file_owner(json_file)
            mtime = get_file_mtime(json_file)

            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue

            if isinstance(data, dict):
                access_token = data.get("accessToken")
                if access_token and isinstance(access_token, str):
                    notes = ["AWS SSO cached token"]
                    if mtime:
                        notes.append(f"File last modified: {describe_staleness(mtime)}")
                    result.findings.append(CredentialFinding(
                        tool_name=self.name(),
                        credential_type="sso_access_token",
                        storage_type=StorageType.PLAINTEXT_JSON,
                        location=str(json_file),
                        exists=True,
                        risk_level=assess_risk(StorageType.PLAINTEXT_JSON, json_file),
                        value_preview=mask_value(access_token, show_full=show_secrets),
                        raw_value=access_token if show_secrets else None,
                        file_permissions=perms,
                        file_owner=owner,
                        file_modified=mtime,
                        remediation="Rotate SSO tokens regularly",
                        remediation_hint=hint_rotate_credential("aws-sso", "Rotate SSO tokens regularly"),
                        notes=notes,
                    ))
