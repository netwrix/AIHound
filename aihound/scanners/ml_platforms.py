"""Scanner for ML inference platform credentials (Replicate / Together / Groq)."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("aihound.scanners.ml_platforms")

from aihound.core.scanner import (
    BaseScanner, CredentialFinding, ScanResult, StorageType,
)
from aihound.core.platform import (
    detect_platform, Platform, get_home, get_appdata, get_wsl_windows_home,
)
from aihound.core.redactor import mask_value
from aihound.core.permissions import (
    get_file_permissions, get_file_owner, assess_risk,
    get_file_mtime, describe_staleness,
)
from aihound.remediation import hint_migrate_to_env
from aihound.scanners import register


SECRET_KEY_TOKENS = ("token", "key", "secret", "api_key", "apikey", "access_key")


@register
class MLPlatformsScanner(BaseScanner):
    def name(self) -> str:
        return "ML Platforms (Replicate/Together/Groq)"

    def slug(self) -> str:
        return "ml-platforms"

    def scan(self, show_secrets: bool = False) -> ScanResult:
        plat = detect_platform()
        result = ScanResult(scanner_name=self.name(), platform=plat.value)

        # (platform_label, plaintext_paths, json_paths)
        for label, plain_paths, json_paths in self._build_all_paths(plat):
            for path in plain_paths:
                self._scan_plaintext(path, label, result, show_secrets)
            for path in json_paths:
                self._scan_json(path, label, result, show_secrets)

        return result

    def _build_all_paths(self, plat: Platform):
        home = get_home()
        win_home = get_wsl_windows_home() if plat == Platform.WSL else None
        appdata = get_appdata() if plat in (Platform.WSL, Platform.WINDOWS) else None

        # Replicate
        replicate_plain = [home / ".replicate" / "auth"]
        replicate_json = [home / ".replicate" / "config.json"]
        if win_home:
            replicate_plain.append(win_home / ".replicate" / "auth")
            replicate_json.append(win_home / ".replicate" / "config.json")
        if appdata:
            replicate_json.append(appdata / "replicate" / "config.json")

        # Together
        together_plain = [home / ".together" / "api_key"]
        together_json = [home / ".together" / "config.json"]
        if win_home:
            together_plain.append(win_home / ".together" / "api_key")
            together_json.append(win_home / ".together" / "config.json")
        if appdata:
            together_json.append(appdata / "together" / "config.json")

        # Groq
        groq_plain = [home / ".groq" / "api_key"]
        groq_json = [home / ".groq" / "config.json"]
        if win_home:
            groq_plain.append(win_home / ".groq" / "api_key")
            groq_json.append(win_home / ".groq" / "config.json")
        if appdata:
            groq_json.append(appdata / "groq" / "config.json")

        return [
            ("replicate", replicate_plain, replicate_json),
            ("together", together_plain, together_json),
            ("groq", groq_plain, groq_json),
        ]

    def _remediation_for(self, label: str) -> str:
        return "Use environment variables (REPLICATE_API_TOKEN, TOGETHER_API_KEY, GROQ_API_KEY) instead of config files"

    def _scan_plaintext(
        self, path: Path, label: str, result: ScanResult, show_secrets: bool
    ) -> None:
        if not path.exists():
            logger.debug("ML plaintext token not found: %s", path)
            return

        logger.debug("Reading ML plaintext token: %s", path)
        perms = get_file_permissions(path)
        owner = get_file_owner(path)
        mtime = get_file_mtime(path)
        storage = StorageType.PLAINTEXT_FILE

        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError as e:
            logger.warning("Failed to read %s: %s", path, e)
            result.errors.append(f"Failed to read {path}: {e}")
            return

        if not value:
            return

        notes = [f"Platform: {label}"]
        if mtime:
            notes.append(f"File last modified: {describe_staleness(mtime)}")

        result.findings.append(CredentialFinding(
            tool_name=self.name(),
            credential_type=f"{label}_api_key",
            storage_type=storage,
            location=str(path),
            exists=True,
            risk_level=assess_risk(storage, path),
            value_preview=mask_value(value, show_full=show_secrets),
            raw_value=value if show_secrets else None,
            file_permissions=perms,
            file_owner=owner,
            file_modified=mtime,
            remediation=self._remediation_for(label),
            remediation_hint=hint_migrate_to_env(
                ["REPLICATE_API_TOKEN", "TOGETHER_API_KEY", "GROQ_API_KEY"], str(path)
            ),
            notes=notes,
        ))

    def _scan_json(
        self, path: Path, label: str, result: ScanResult, show_secrets: bool
    ) -> None:
        if not path.exists():
            logger.debug("ML JSON config not found: %s", path)
            return

        logger.debug("Reading ML JSON config: %s", path)
        perms = get_file_permissions(path)
        owner = get_file_owner(path)
        mtime = get_file_mtime(path)

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to parse %s: %s", path, e)
            result.errors.append(f"Failed to parse {path}: {e}")
            return

        self._walk_json(data, path, label, perms, owner, mtime, result, show_secrets, key_path="")

    def _walk_json(
        self,
        data,
        path: Path,
        label: str,
        perms: Optional[str],
        owner: Optional[str],
        mtime,
        result: ScanResult,
        show_secrets: bool,
        key_path: str,
    ) -> None:
        storage = StorageType.PLAINTEXT_JSON

        if isinstance(data, dict):
            for k, v in data.items():
                if not isinstance(k, str):
                    continue
                sub_path = f"{key_path}.{k}" if key_path else k

                if isinstance(v, str) and v:
                    k_lower = k.lower()
                    if any(tok in k_lower for tok in SECRET_KEY_TOKENS) and len(v) > 8:
                        notes = [f"Platform: {label}", f"JSON key path: {sub_path}"]
                        if mtime:
                            notes.append(f"File last modified: {describe_staleness(mtime)}")
                        result.findings.append(CredentialFinding(
                            tool_name=self.name(),
                            credential_type=f"{label}:{k}",
                            storage_type=storage,
                            location=str(path),
                            exists=True,
                            risk_level=assess_risk(storage, path),
                            value_preview=mask_value(v, show_full=show_secrets),
                            raw_value=v if show_secrets else None,
                            file_permissions=perms,
                            file_owner=owner,
                            file_modified=mtime,
                            remediation=self._remediation_for(label),
                            remediation_hint=hint_migrate_to_env(
                                ["REPLICATE_API_TOKEN", "TOGETHER_API_KEY", "GROQ_API_KEY"], str(path)
                            ),
                            notes=notes,
                        ))
                elif isinstance(v, (dict, list)):
                    self._walk_json(v, path, label, perms, owner, mtime, result, show_secrets, sub_path)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                sub_path = f"{key_path}[{i}]"
                if isinstance(item, (dict, list)):
                    self._walk_json(item, path, label, perms, owner, mtime, result, show_secrets, sub_path)
