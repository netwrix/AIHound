"""Scanner for Git credential store and global gitconfig URLs."""

from __future__ import annotations

import configparser
import logging
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger("aihound.scanners.git_credentials")

from aihound.core.scanner import (
    BaseScanner, CredentialFinding, ScanResult, StorageType,
)
from aihound.core.platform import (
    detect_platform, Platform, get_home, get_wsl_windows_home, get_xdg_config,
)
from aihound.core.redactor import mask_value
from aihound.core.permissions import (
    get_file_permissions, get_file_owner, assess_risk,
    get_file_mtime, describe_staleness,
)
from aihound.remediation import hint_use_credential_helper, hint_manual
from aihound.scanners import register


@register
class GitCredentialsScanner(BaseScanner):
    def name(self) -> str:
        return "Git Credentials"

    def slug(self) -> str:
        return "git-credentials"

    def scan(self, show_secrets: bool = False) -> ScanResult:
        plat = detect_platform()
        result = ScanResult(scanner_name=self.name(), platform=plat.value)

        for path in self._get_credential_store_paths(plat):
            self._scan_credentials_file(path, result, show_secrets)

        for path in self._get_gitconfig_paths(plat):
            self._scan_gitconfig(path, result, show_secrets)

        return result

    def _get_credential_store_paths(self, plat: Platform) -> list[Path]:
        paths: list[Path] = []
        home = get_home()

        paths.append(home / ".git-credentials")

        # XDG location
        xdg_config = get_xdg_config()
        paths.append(xdg_config / "git" / "credentials")

        if plat == Platform.WSL:
            win_home = get_wsl_windows_home()
            if win_home:
                paths.append(win_home / ".git-credentials")

        return paths

    def _get_gitconfig_paths(self, plat: Platform) -> list[Path]:
        paths: list[Path] = []
        home = get_home()

        paths.append(home / ".gitconfig")
        paths.append(get_xdg_config() / "git" / "config")

        if plat == Platform.WSL:
            win_home = get_wsl_windows_home()
            if win_home:
                paths.append(win_home / ".gitconfig")

        return paths

    def _scan_credentials_file(
        self, path: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        if not path.exists():
            logger.debug("Git credentials file not found: %s", path)
            return

        logger.debug("Reading git credentials file: %s", path)
        perms = get_file_permissions(path)
        owner = get_file_owner(path)
        mtime = get_file_mtime(path)
        storage = StorageType.PLAINTEXT_FILE

        try:
            content = path.read_text(encoding="utf-8")
        except OSError as e:
            logger.warning("Failed to read %s: %s", path, e)
            result.errors.append(f"Failed to read {path}: {e}")
            return

        try:
            for line_num, raw_line in enumerate(content.splitlines(), start=1):
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue

                try:
                    parsed = urlparse(line)
                except ValueError:
                    continue

                if not parsed.scheme:
                    continue

                username = parsed.username or ""
                password = parsed.password or ""
                if not password:
                    continue

                host = parsed.hostname or "?"
                notes = [f"Host: {host}", f"Username: {username or '(none)'}", f"Line: {line_num}"]
                if mtime:
                    notes.append(f"File last modified: {describe_staleness(mtime)}")

                result.findings.append(CredentialFinding(
                    tool_name=self.name(),
                    credential_type=f"git_credential:{host}",
                    storage_type=storage,
                    location=str(path),
                    exists=True,
                    risk_level=assess_risk(storage, path),
                    value_preview=mask_value(password, show_full=show_secrets),
                    raw_value=password if show_secrets else None,
                    file_permissions=perms,
                    file_owner=owner,
                    file_modified=mtime,
                    remediation="Use a secure credential helper (osxkeychain, manager, libsecret) instead of plaintext store",
                    remediation_hint=hint_use_credential_helper(
                        "git", ["osxkeychain", "manager", "libsecret"]
                    ),
                    notes=notes,
                ))
        except Exception as e:
            logger.warning("Failed to parse %s: %s", path, e, exc_info=True)
            result.errors.append(f"Failed to parse {path}: {e}")

    def _scan_gitconfig(
        self, path: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        if not path.exists():
            logger.debug("Git config not found: %s", path)
            return

        logger.debug("Reading git config: %s", path)
        perms = get_file_permissions(path)
        owner = get_file_owner(path)
        mtime = get_file_mtime(path)
        storage = StorageType.PLAINTEXT_INI

        # Git config uses INI-like syntax. Use configparser with strict=False.
        config = configparser.ConfigParser(strict=False)
        try:
            config.read(str(path), encoding="utf-8")
        except (configparser.Error, OSError) as e:
            logger.warning("Failed to parse %s: %s", path, e)
            result.errors.append(f"Failed to parse {path}: {e}")
            return

        for section in config.sections():
            section_lower = section.lower()

            for key, value in config.items(section):
                if not value:
                    continue

                key_lower = key.lower()

                # 1) Any url = https://user:token@... entry
                if key_lower == "url" and isinstance(value, str):
                    try:
                        parsed = urlparse(value)
                    except ValueError:
                        parsed = None
                    if parsed and parsed.password:
                        host = parsed.hostname or "?"
                        username = parsed.username or ""
                        notes = [
                            f"Section: [{section}]",
                            f"Host: {host}",
                            f"Username: {username or '(none)'}",
                        ]
                        if mtime:
                            notes.append(f"File last modified: {describe_staleness(mtime)}")

                        result.findings.append(CredentialFinding(
                            tool_name=self.name(),
                            credential_type=f"gitconfig_url:{host}",
                            storage_type=storage,
                            location=str(path),
                            exists=True,
                            risk_level=assess_risk(storage, path),
                            value_preview=mask_value(parsed.password, show_full=show_secrets),
                            raw_value=parsed.password if show_secrets else None,
                            file_permissions=perms,
                            file_owner=owner,
                            file_modified=mtime,
                            remediation="Remove embedded credentials from gitconfig URL; use a credential helper instead",
                            remediation_hint=hint_use_credential_helper(
                                "git", ["osxkeychain", "manager", "libsecret"]
                            ),
                            notes=notes,
                        ))

                # 2) [credential] sections: any key that looks like a secret
                if section_lower.startswith("credential"):
                    if any(tok in key_lower for tok in ("helper", "username", "usehttppath")):
                        continue
                    if any(tok in key_lower for tok in ("password", "token", "secret", "key")):
                        notes = [f"Section: [{section}]", f"Key: {key}"]
                        if mtime:
                            notes.append(f"File last modified: {describe_staleness(mtime)}")

                        result.findings.append(CredentialFinding(
                            tool_name=self.name(),
                            credential_type=f"gitconfig_credential:{key}",
                            storage_type=storage,
                            location=str(path),
                            exists=True,
                            risk_level=assess_risk(storage, path),
                            value_preview=mask_value(value, show_full=show_secrets),
                            raw_value=value if show_secrets else None,
                            file_permissions=perms,
                            file_owner=owner,
                            file_modified=mtime,
                            remediation="Use a secure credential helper (osxkeychain, manager, libsecret) instead of plaintext store",
                            remediation_hint=hint_use_credential_helper(
                                "git", ["osxkeychain", "manager", "libsecret"]
                            ),
                            notes=notes,
                        ))
