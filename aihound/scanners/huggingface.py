"""Scanner for Hugging Face CLI token file."""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger("aihound.scanners.huggingface")

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


@register
class HuggingFaceScanner(BaseScanner):
    def name(self) -> str:
        return "Hugging Face CLI"

    def slug(self) -> str:
        return "huggingface"

    def scan(self, show_secrets: bool = False) -> ScanResult:
        plat = detect_platform()
        result = ScanResult(scanner_name=self.name(), platform=plat.value)

        for path in self._get_token_paths(plat):
            self._scan_token_file(path, result, show_secrets)

        return result

    def _get_token_paths(self, plat: Platform) -> list[Path]:
        paths: list[Path] = []
        home = get_home()

        paths.append(home / ".cache" / "huggingface" / "token")
        paths.append(home / ".huggingface" / "token")

        if plat == Platform.WSL:
            win_home = get_wsl_windows_home()
            if win_home:
                paths.append(win_home / ".cache" / "huggingface" / "token")
                paths.append(win_home / ".huggingface" / "token")

        return paths

    def _scan_token_file(
        self, path: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        if not path.exists():
            logger.debug("HF token file not found: %s", path)
            return

        logger.debug("Reading HF token file: %s", path)
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

        notes: list[str] = []
        if mtime:
            notes.append(f"File last modified: {describe_staleness(mtime)}")

        result.findings.append(CredentialFinding(
            tool_name=self.name(),
            credential_type="hf_token",
            storage_type=storage,
            location=str(path),
            exists=True,
            risk_level=assess_risk(storage, path),
            value_preview=mask_value(value, show_full=show_secrets),
            raw_value=value if show_secrets else None,
            file_permissions=perms,
            file_owner=owner,
            file_modified=mtime,
            remediation="Use HF_TOKEN environment variable instead of plaintext token file",
            remediation_hint=hint_migrate_to_env(["HF_TOKEN"], str(path)),
            notes=notes,
        ))
