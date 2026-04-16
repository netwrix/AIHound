"""Scanner for Aider configuration files."""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger("aihound.scanners.aider")

from aihound.core.scanner import (
    BaseScanner, CredentialFinding, ScanResult, StorageType,
)
from aihound.core.platform import detect_platform, Platform, get_home, get_wsl_windows_home
from aihound.core.redactor import mask_value
from aihound.core.permissions import (
    get_file_permissions, get_file_owner, assess_risk,
    get_file_mtime, describe_staleness,
)
from aihound.remediation import hint_migrate_to_env
from aihound.scanners import register


SECRET_KEY_TOKENS = ("key", "token", "secret", "password", "passwd", "auth", "credential")


@register
class AiderScanner(BaseScanner):
    def name(self) -> str:
        return "Aider"

    def slug(self) -> str:
        return "aider"

    def scan(self, show_secrets: bool = False) -> ScanResult:
        plat = detect_platform()
        result = ScanResult(scanner_name=self.name(), platform=plat.value)

        for path in self._get_config_paths(plat):
            self._scan_config(path, result, show_secrets)

        return result

    def _get_config_paths(self, plat: Platform) -> list[Path]:
        paths: list[Path] = []
        home = get_home()

        # Linux/macOS/Windows: ~/.aider.conf.yml (and .yaml)
        paths.append(home / ".aider.conf.yml")
        paths.append(home / ".aider.conf.yaml")

        # WSL: also check Windows user home
        if plat == Platform.WSL:
            win_home = get_wsl_windows_home()
            if win_home:
                paths.append(win_home / ".aider.conf.yml")
                paths.append(win_home / ".aider.conf.yaml")

        return paths

    def _scan_config(
        self, path: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        if not path.exists():
            logger.debug("Aider config not found: %s", path)
            return

        logger.debug("Reading Aider config: %s", path)
        perms = get_file_permissions(path)
        owner = get_file_owner(path)
        mtime = get_file_mtime(path)
        storage = StorageType.PLAINTEXT_YAML

        try:
            content = path.read_text(encoding="utf-8")
        except OSError as e:
            logger.warning("Failed to read %s: %s", path, e)
            result.errors.append(f"Failed to read {path}: {e}")
            return

        try:
            for line in content.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if ":" not in stripped:
                    continue

                key, _, value = stripped.partition(":")
                key = key.strip()
                value = value.strip()

                if not value:
                    continue

                # Strip inline comments
                if "#" in value:
                    # Only strip if not inside quotes; simple heuristic
                    if not (value.startswith('"') or value.startswith("'")):
                        value = value.split("#", 1)[0].strip()

                # Strip surrounding quotes
                if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                    value = value[1:-1]

                if not value:
                    continue

                key_lower = key.lower()
                if not any(tok in key_lower for tok in SECRET_KEY_TOKENS):
                    continue

                # Skip obvious non-secret values: booleans, numbers
                if value.lower() in ("true", "false", "yes", "no", "null", "~"):
                    continue

                notes = [f"Aider config key: {key}"]
                if mtime:
                    notes.append(f"File last modified: {describe_staleness(mtime)}")

                result.findings.append(CredentialFinding(
                    tool_name=self.name(),
                    credential_type=f"aider:{key}",
                    storage_type=storage,
                    location=str(path),
                    exists=True,
                    risk_level=assess_risk(storage, path),
                    value_preview=mask_value(value, show_full=show_secrets),
                    raw_value=value if show_secrets else None,
                    file_permissions=perms,
                    file_owner=owner,
                    file_modified=mtime,
                    remediation="Use environment variables (OPENAI_API_KEY, ANTHROPIC_API_KEY) instead of config file",
                    remediation_hint=hint_migrate_to_env(["OPENAI_API_KEY", "ANTHROPIC_API_KEY"], path),
                    notes=notes,
                ))
        except Exception as e:
            logger.warning("Failed to parse %s: %s", path, e, exc_info=True)
            result.errors.append(f"Failed to parse {path}: {e}")
