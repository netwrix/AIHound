"""Scanner for Continue.dev credentials."""

from __future__ import annotations

import json
from pathlib import Path

from aihound.core.scanner import (
    BaseScanner, CredentialFinding, ScanResult, StorageType, RiskLevel,
)
from aihound.core.platform import detect_platform, Platform, get_home, get_wsl_windows_home
from aihound.core.redactor import mask_value
from aihound.core.permissions import get_file_permissions, get_file_owner, assess_risk, get_file_mtime, describe_staleness
from aihound.remediation import hint_migrate_to_env
from aihound.scanners import register


@register
class ContinueDevScanner(BaseScanner):
    def name(self) -> str:
        return "Continue.dev"

    def slug(self) -> str:
        return "continue-dev"

    def scan(self, show_secrets: bool = False) -> ScanResult:
        plat = detect_platform()
        result = ScanResult(scanner_name=self.name(), platform=plat.value)

        for path in self._get_config_paths(plat):
            self._scan_config(path, result, show_secrets)

        return result

    def _get_config_paths(self, plat: Platform) -> list[Path]:
        paths = []
        home = get_home()

        # ~/.continue/config.json (all platforms)
        paths.append(home / ".continue" / "config.json")
        # Newer YAML format
        paths.append(home / ".continue" / "config.yaml")

        if plat == Platform.WSL:
            win_home = get_wsl_windows_home()
            if win_home:
                paths.append(win_home / ".continue" / "config.json")
                paths.append(win_home / ".continue" / "config.yaml")

        return paths

    def _scan_config(
        self, path: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        if not path.exists():
            return

        perms = get_file_permissions(path)
        owner = get_file_owner(path)
        mtime = get_file_mtime(path)

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            result.errors.append(f"Failed to parse {path}: {e}")
            return

        # Check models array for API keys
        models = data.get("models", [])
        if isinstance(models, list):
            for model in models:
                if not isinstance(model, dict):
                    continue
                api_key = model.get("apiKey", "")
                if api_key and isinstance(api_key, str):
                    is_env_ref = "${" in api_key
                    provider = model.get("provider", "unknown")

                    if is_env_ref:
                        notes = ["References env var (not inline)"]
                        if mtime:
                            notes.append(f"File last modified: {describe_staleness(mtime)}")
                        result.findings.append(CredentialFinding(
                            tool_name=self.name(),
                            credential_type=f"api_key ({provider})",
                            storage_type=StorageType.PLAINTEXT_JSON,
                            location=str(path),
                            exists=True,
                            risk_level=RiskLevel.INFO,
                            value_preview=api_key,
                            file_permissions=perms,
                            file_owner=owner,
                            file_modified=mtime,
                            notes=notes,
                        ))
                    else:
                        notes = ["PLAINTEXT API key in config!"]
                        if mtime:
                            notes.append(f"File last modified: {describe_staleness(mtime)}")
                        result.findings.append(CredentialFinding(
                            tool_name=self.name(),
                            credential_type=f"api_key ({provider})",
                            storage_type=StorageType.PLAINTEXT_JSON,
                            location=str(path),
                            exists=True,
                            risk_level=assess_risk(StorageType.PLAINTEXT_JSON, path),
                            value_preview=mask_value(api_key, show_full=show_secrets),
                            raw_value=api_key if show_secrets else None,
                            file_permissions=perms,
                            file_owner=owner,
                            file_modified=mtime,
                            remediation="Use environment variables instead of inline API keys in config",
                            remediation_hint=hint_migrate_to_env([], str(path)),
                            notes=notes,
                        ))

        # Check tabAutocompleteModel
        tab_model = data.get("tabAutocompleteModel", {})
        if isinstance(tab_model, dict):
            api_key = tab_model.get("apiKey", "")
            if api_key and isinstance(api_key, str) and "${" not in api_key:
                notes = ["PLAINTEXT API key in config!"]
                if mtime:
                    notes.append(f"File last modified: {describe_staleness(mtime)}")
                result.findings.append(CredentialFinding(
                    tool_name=self.name(),
                    credential_type="tabAutocomplete api_key",
                    storage_type=StorageType.PLAINTEXT_JSON,
                    location=str(path),
                    exists=True,
                    risk_level=assess_risk(StorageType.PLAINTEXT_JSON, path),
                    value_preview=mask_value(api_key, show_full=show_secrets),
                    raw_value=api_key if show_secrets else None,
                    file_permissions=perms,
                    file_owner=owner,
                    file_modified=mtime,
                    remediation="Use environment variables instead of inline API keys in config",
                    remediation_hint=hint_migrate_to_env([], str(path)),
                    notes=notes,
                ))

