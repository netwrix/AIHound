"""Scanner for shell RC/profile files and .env files for hardcoded AI credentials."""

from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger("aihound.scanners.shell_rc")

from aihound.core.scanner import (
    BaseScanner, CredentialFinding, ScanResult, StorageType, RiskLevel,
)
from aihound.core.platform import detect_platform, Platform, get_home, get_wsl_windows_home
from aihound.core.redactor import mask_value, identify_credential_type, KNOWN_PREFIXES, redact_line
from aihound.core.permissions import (
    get_file_permissions, get_file_owner, assess_risk,
    get_file_mtime, describe_staleness,
)
from aihound.remediation import hint_manual
from aihound.scanners import register
from aihound.scanners.envvars import AI_ENV_VARS


# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

# bash/zsh: export VAR="value" or export VAR=value
_EXPORT_RE = re.compile(
    r"""
    ^
    export \s+
    (?P<var>[A-Za-z_][A-Za-z0-9_]*)   # variable name
    \s* = \s*
    ["']?                               # optional opening quote
    (?P<value>[^\s"'\n]+)               # the value (no whitespace/quotes)
    ["']?                               # optional closing quote
    """,
    re.MULTILINE | re.VERBOSE,
)

# fish: set -gx VAR value  or  set -x VAR value
_FISH_SET_RE = re.compile(
    r"""
    ^
    set \s+
    (?:-[a-zA-Z]+ \s+)*                # optional flags like -gx, -x, etc.
    (?P<var>[A-Za-z_][A-Za-z0-9_]*)   # variable name
    \s+
    ["']?                               # optional opening quote
    (?P<value>[^\s"'\n]+)               # value
    ["']?                               # optional closing quote
    """,
    re.MULTILINE | re.VERBOSE,
)

# PowerShell: $env:VAR = "value"
_PS_ENV_RE = re.compile(
    r"""
    ^
    \$env:
    (?P<var>[A-Za-z_][A-Za-z0-9_]*)   # variable name
    \s* = \s*
    ["']?                               # optional opening quote
    (?P<value>[^\s"'\n]+)               # value
    ["']?                               # optional closing quote
    """,
    re.MULTILINE | re.VERBOSE,
)

# .env file: VAR=value  (no export prefix)
_DOTENV_RE = re.compile(
    r"""
    ^
    (?P<var>[A-Za-z_][A-Za-z0-9_]*)   # variable name
    \s* = \s*
    ["']?                               # optional opening quote
    (?P<value>[^\s"'\n]+)               # value
    ["']?                               # optional closing quote
    """,
    re.MULTILINE | re.VERBOSE,
)

# Raw known-prefix token anywhere on the line
_PREFIX_PATTERN = "|".join(
    re.escape(p) for p in sorted(KNOWN_PREFIXES.keys(), key=len, reverse=True)
)
_RAW_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_\-])((?:" + _PREFIX_PATTERN + r")[A-Za-z0-9_\-./+=]{16,})"
)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

@register
class ShellRcScanner(BaseScanner):
    def name(self) -> str:
        return "Shell RC Files"

    def slug(self) -> str:
        return "shell-rc"

    def scan(self, show_secrets: bool = False) -> ScanResult:
        plat = detect_platform()
        result = ScanResult(scanner_name=self.name(), platform=plat.value)

        # Scan shell RC files
        for path in self._get_rc_paths(plat):
            self._scan_file(path, result, show_secrets)

        # Scan .env files
        for path in self._get_env_paths(plat):
            self._scan_file(path, result, show_secrets)

        return result

    def _get_rc_paths(self, plat: Platform) -> list[Path]:
        """Return list of shell RC/profile file paths to scan for this platform."""
        home = get_home()
        paths: list[Path] = []

        if plat in (Platform.LINUX, Platform.MACOS, Platform.WSL):
            # bash
            paths.append(home / ".bashrc")
            paths.append(home / ".bash_profile")
            paths.append(home / ".profile")
            # zsh
            paths.append(home / ".zshrc")
            paths.append(home / ".zprofile")
            paths.append(home / ".zshenv")
            # fish
            paths.append(home / ".config" / "fish" / "config.fish")

        if plat == Platform.WINDOWS:
            # PowerShell profiles
            paths.append(
                home / "Documents" / "PowerShell" / "Microsoft.PowerShell_profile.ps1"
            )
            paths.append(
                home / "Documents" / "WindowsPowerShell" / "Microsoft.PowerShell_profile.ps1"
            )

        if plat == Platform.WSL:
            # Also scan Windows-side PowerShell profiles
            win_home = get_wsl_windows_home()
            if win_home:
                paths.append(
                    win_home / "Documents" / "PowerShell" / "Microsoft.PowerShell_profile.ps1"
                )
                paths.append(
                    win_home / "Documents" / "WindowsPowerShell" / "Microsoft.PowerShell_profile.ps1"
                )

        return paths

    def _get_env_paths(self, plat: Platform) -> list[Path]:
        """Return list of .env file paths to scan for this platform."""
        home = get_home()
        paths: list[Path] = [
            home / ".env",
            home / ".config" / ".env",
            home / ".docker" / ".env",
            home / ".config" / "fish" / ".env",
            home / ".local" / ".env",
        ]

        if plat == Platform.WSL:
            win_home = get_wsl_windows_home()
            if win_home:
                paths.append(win_home / ".env")

        return paths

    def _is_env_file(self, path: Path) -> bool:
        """Return True if this path is a .env file."""
        return path.name == ".env" or path.suffix == ".env"

    def _scan_file(self, path: Path, result: ScanResult, show_secrets: bool) -> None:
        """Read a file and add any findings to result."""
        if not path.exists():
            logger.debug("Shell RC file not found: %s", path)
            return

        logger.debug("Scanning shell RC file: %s", path)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.warning("Failed to read %s: %s", path, e)
            result.errors.append(f"Failed to read {path}: {e}")
            return

        for finding in self._scan_content(text, path, show_secrets):
            result.findings.append(finding)

    def _scan_content(
        self, text: str, path: Path, show_secrets: bool
    ) -> list[CredentialFinding]:
        """Parse text and return findings. Does not require the file to exist."""
        findings: list[CredentialFinding] = []
        seen_values: set[str] = set()
        is_env = self._is_env_file(path)
        storage = StorageType.PLAINTEXT_ENV if is_env else StorageType.PLAINTEXT_FILE

        # Determine which assignment patterns to apply based on file type/extension
        suffix = path.suffix.lower()
        name = path.name.lower()
        is_ps = suffix == ".ps1"
        is_fish = "fish" in str(path) and name.endswith(".fish")

        if is_env:
            assignment_patterns = [_DOTENV_RE]
        elif is_ps:
            assignment_patterns = [_PS_ENV_RE]
        elif is_fish:
            assignment_patterns = [_FISH_SET_RE, _EXPORT_RE]
        else:
            # bash/zsh/profile: use export pattern primarily, also dotenv as fallback
            assignment_patterns = [_EXPORT_RE, _DOTENV_RE]

        # Pass 1: Variable assignment patterns
        for pattern in assignment_patterns:
            for match in pattern.finditer(text):
                var_name = match.group("var")
                value = match.group("value").strip("'\"")

                # Only flag if var is a known AI env var OR value matches a known prefix
                if var_name not in AI_ENV_VARS and not identify_credential_type(value):
                    continue

                if value in seen_values:
                    continue
                seen_values.add(value)

                line_num = text[: match.start()].count("\n") + 1
                line_text = text.splitlines()[line_num - 1] if text.splitlines() else ""

                cred_type = AI_ENV_VARS.get(var_name) or identify_credential_type(value) or "api-key"
                findings.append(self._make_finding(
                    path=path,
                    value=value,
                    line_num=line_num,
                    line_text=line_text,
                    cred_type=cred_type,
                    storage=storage,
                    show_secrets=show_secrets,
                ))

        # Pass 2: Raw known-prefix tokens anywhere on any line
        for match in _RAW_TOKEN_RE.finditer(text):
            value = match.group(1)
            if value in seen_values:
                continue
            seen_values.add(value)

            line_num = text[: match.start()].count("\n") + 1
            line_text = text.splitlines()[line_num - 1] if text.splitlines() else ""

            cred_type = identify_credential_type(value) or "api-key"
            findings.append(self._make_finding(
                path=path,
                value=value,
                line_num=line_num,
                line_text=line_text,
                cred_type=cred_type,
                storage=storage,
                show_secrets=show_secrets,
            ))

        return findings

    def _make_finding(
        self,
        *,
        path: Path,
        value: str,
        line_num: int,
        line_text: str,
        cred_type: str,
        storage: StorageType,
        show_secrets: bool,
    ) -> CredentialFinding:
        perms = get_file_permissions(path) if path.exists() else None
        owner = get_file_owner(path) if path.exists() else None
        mtime = get_file_mtime(path) if path.exists() else None

        notes: list[str] = [f"Line {line_num}: {redact_line(line_text)[:120]}"]
        if mtime:
            notes.append(f"File last modified: {describe_staleness(mtime)}")

        risk = assess_risk(storage, path)

        return CredentialFinding(
            tool_name=self.name(),
            credential_type=cred_type,
            storage_type=storage,
            location=f"{path}:{line_num}",
            exists=True,
            risk_level=risk,
            value_preview=mask_value(value, show_full=show_secrets),
            raw_value=value if show_secrets else None,
            file_permissions=perms,
            file_owner=owner,
            file_modified=mtime,
            remediation=(
                "Remove credentials from shell config files. "
                "Use a secret manager or source a gitignored file instead."
            ),
            remediation_hint=hint_manual(
                "Remove credential from shell config and use a secret manager",
                suggested_tools=["1Password CLI", "doppler", "vault"],
            ),
            notes=notes,
        )
